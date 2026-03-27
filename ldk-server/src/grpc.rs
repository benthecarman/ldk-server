// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! gRPC wire protocol primitives implemented directly on HTTP/2 via hyper,
//! without depending on tonic or any gRPC framework.

use std::pin::Pin;
use std::task::{Context, Poll};

use base64::Engine;
use bytes::{BufMut, Bytes, BytesMut};
use hyper::body::{Frame, Incoming};
use hyper::header::HeaderValue;
use hyper::http::HeaderMap;
use hyper::{Request, Response};
use tokio::sync::mpsc;

use crate::api::error::{LdkServerError, LdkServerErrorCode};

// gRPC status codes (a subset — only those we use).
#[allow(dead_code)] // Used by streaming responses (SubscribeEvents)
pub(crate) const GRPC_STATUS_OK: u32 = 0;
pub(crate) const GRPC_STATUS_INVALID_ARGUMENT: u32 = 3;
pub(crate) const GRPC_STATUS_DEADLINE_EXCEEDED: u32 = 4;
pub(crate) const GRPC_STATUS_FAILED_PRECONDITION: u32 = 9;
pub(crate) const GRPC_STATUS_UNIMPLEMENTED: u32 = 12;
pub(crate) const GRPC_STATUS_INTERNAL: u32 = 13;
pub(crate) const GRPC_STATUS_UNAVAILABLE: u32 = 14;
pub(crate) const GRPC_STATUS_UNAUTHENTICATED: u32 = 16;

/// A gRPC status with code and human-readable message.
#[derive(Debug)]
pub(crate) struct GrpcStatus {
	pub code: u32,
	pub message: String,
}

impl GrpcStatus {
	pub(crate) fn new(code: u32, message: impl Into<String>) -> Self {
		Self { code, message: message.into() }
	}
}

/// Decode a gRPC-framed request body, returning the inner protobuf bytes.
///
/// gRPC framing: 1 byte compressed flag + 4 bytes big-endian length + payload.
pub(crate) fn decode_grpc_body(bytes: &[u8]) -> Result<&[u8], GrpcStatus> {
	if bytes.len() < 5 {
		return Err(GrpcStatus::new(
			GRPC_STATUS_INVALID_ARGUMENT,
			"Request body too short for gRPC frame",
		));
	}

	// gRPC Compressed-Flag: 0 = uncompressed, 1 = compressed per grpc-encoding header.
	// We don't support compression because our RPCs exchange small protobuf messages where
	// compression overhead would outweigh savings. Returning UNIMPLEMENTED causes compliant
	// clients to retry without compression.
	let compressed = bytes[0];
	if compressed != 0 {
		return Err(GrpcStatus::new(
			GRPC_STATUS_UNIMPLEMENTED,
			"gRPC compression is not supported",
		));
	}

	let len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
	if bytes.len() < 5 + len {
		return Err(GrpcStatus::new(
			GRPC_STATUS_INVALID_ARGUMENT,
			"gRPC frame length exceeds body size",
		));
	}

	if bytes.len() > 5 + len {
		return Err(GrpcStatus::new(
			GRPC_STATUS_INVALID_ARGUMENT,
			"Trailing data after gRPC frame",
		));
	}

	Ok(&bytes[5..5 + len])
}

/// Encode a protobuf message into a gRPC-framed `Bytes`.
///
/// gRPC framing: 1 byte compressed flag (0) + 4 bytes big-endian length + payload.
pub(crate) fn encode_grpc_frame(proto_bytes: &[u8]) -> Bytes {
	debug_assert!(
		proto_bytes.len() <= u32::MAX as usize,
		"gRPC message exceeds maximum frame size (4 GB)"
	);
	let mut buf = BytesMut::with_capacity(5 + proto_bytes.len());
	buf.put_u8(0); // no compression
	buf.put_u32(proto_bytes.len() as u32);
	buf.put_slice(proto_bytes);
	buf.freeze()
}

/// Map an `LdkServerError` to a `GrpcStatus`.
pub(crate) fn ldk_error_to_grpc_status(e: LdkServerError) -> GrpcStatus {
	let code = match e.error_code {
		LdkServerErrorCode::InvalidRequestError => GRPC_STATUS_INVALID_ARGUMENT,
		LdkServerErrorCode::AuthError => GRPC_STATUS_UNAUTHENTICATED,
		LdkServerErrorCode::LightningError => GRPC_STATUS_FAILED_PRECONDITION,
		LdkServerErrorCode::InternalServerError => GRPC_STATUS_INTERNAL,
	};
	GrpcStatus { code, message: e.message }
}

/// Build trailers for a successful gRPC response.
fn ok_trailers() -> HeaderMap {
	let mut trailers = HeaderMap::with_capacity(1);
	trailers.insert("grpc-status", HeaderValue::from_static("0"));
	trailers
}

/// Build trailers for a gRPC error response.
fn error_trailers(status: &GrpcStatus) -> HeaderMap {
	let mut trailers = HeaderMap::with_capacity(2);
	trailers.insert("grpc-status", HeaderValue::from_str(&status.code.to_string()).unwrap());
	if !status.message.is_empty() {
		// Percent-encode the message per gRPC spec.
		let encoded = percent_encode(&status.message);
		if let Ok(val) = HeaderValue::from_str(&encoded) {
			trailers.insert("grpc-message", val);
		}
	}
	trailers
}

/// Minimal percent-encoding for grpc-message (RFC 3986 unreserved chars pass through).
fn percent_encode(s: &str) -> String {
	let mut out = String::with_capacity(s.len());
	for b in s.bytes() {
		match b {
			b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b' ' => {
				out.push(b as char)
			},
			_ => {
				out.push('%');
				out.push(char::from(b"0123456789ABCDEF"[(b >> 4) as usize]));
				out.push(char::from(b"0123456789ABCDEF"[(b & 0xf) as usize]));
			},
		}
	}
	out
}

/// A response body type for gRPC over HTTP/2.
///
/// Implements `http_body::Body` to deliver gRPC-framed data followed by trailers.
pub(crate) enum GrpcBody {
	/// A single gRPC-framed message followed by OK trailers.
	Unary { data: Option<Bytes>, trailers_sent: bool },
	/// Empty body for Trailers-Only responses (error status is in the HTTP response headers).
	Empty,
	/// Multiple gRPC-framed messages streamed from a channel, followed by trailers.
	/// Send `Err(GrpcStatus)` to terminate the stream with an error status.
	Stream { rx: mpsc::Receiver<Result<Bytes, GrpcStatus>>, done: bool },
}

impl hyper::body::Body for GrpcBody {
	type Data = Bytes;
	type Error = hyper::Error;

	fn poll_frame(
		self: Pin<&mut Self>, _cx: &mut Context<'_>,
	) -> Poll<Option<Result<Frame<Self::Data>, hyper::Error>>> {
		let this = self.get_mut();
		match this {
			GrpcBody::Unary { data, trailers_sent } => {
				if let Some(bytes) = data.take() {
					Poll::Ready(Some(Ok(Frame::data(bytes))))
				} else if !*trailers_sent {
					*trailers_sent = true;
					Poll::Ready(Some(Ok(Frame::trailers(ok_trailers()))))
				} else {
					Poll::Ready(None)
				}
			},
			GrpcBody::Empty => Poll::Ready(None),
			GrpcBody::Stream { rx, done } => {
				if *done {
					return Poll::Ready(None);
				}
				match rx.poll_recv(_cx) {
					Poll::Ready(Some(Ok(bytes))) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
					Poll::Ready(Some(Err(status))) => {
						*done = true;
						Poll::Ready(Some(Ok(Frame::trailers(error_trailers(&status)))))
					},
					Poll::Ready(None) => {
						// Channel closed normally — send OK trailers
						*done = true;
						Poll::Ready(Some(Ok(Frame::trailers(ok_trailers()))))
					},
					Poll::Pending => Poll::Pending,
				}
			},
		}
	}
}

/// Build a Trailers-Only gRPC error response.
///
/// Per the gRPC spec, error responses with no body encode `grpc-status` and `grpc-message`
/// in the HTTP response headers so the entire response is a single HEADERS frame with
/// END_STREAM. This is required for compatibility with strict client implementations
/// (grpc-go, grpc-java).
pub(crate) fn grpc_error_response(status: GrpcStatus) -> Response<GrpcBody> {
	let mut builder = Response::builder()
		.status(200)
		.header("content-type", "application/grpc+proto")
		.header("grpc-accept-encoding", "identity")
		.header("grpc-status", status.code.to_string());
	if !status.message.is_empty() {
		let encoded = percent_encode(&status.message);
		if let Ok(val) = HeaderValue::from_str(&encoded) {
			builder = builder.header("grpc-message", val);
		}
	}
	builder.body(GrpcBody::Empty).unwrap()
}

/// Build an HTTP 200 response with gRPC content-type and the given body.
pub(crate) fn grpc_response(body: GrpcBody) -> Response<GrpcBody> {
	Response::builder()
		.status(200)
		.header("content-type", "application/grpc+proto")
		.header("grpc-accept-encoding", "identity")
		.body(body)
		.unwrap()
}

/// Validate that the request looks like a gRPC call.
pub(crate) fn validate_grpc_request(req: &Request<Incoming>) -> Result<(), GrpcStatus> {
	if req.method() != hyper::Method::POST {
		return Err(GrpcStatus::new(GRPC_STATUS_UNIMPLEMENTED, "gRPC requires POST method"));
	}

	let content_type =
		req.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("");

	if content_type != "application/grpc" && content_type != "application/grpc+proto" {
		return Err(GrpcStatus::new(GRPC_STATUS_INVALID_ARGUMENT, "Invalid content-type for gRPC"));
	}

	Ok(())
}

/// Parse the `grpc-timeout` header value into a `Duration`.
///
/// Format: `<number><unit>` where unit is one of:
/// `H` (hours), `M` (minutes), `S` (seconds), `m` (milliseconds),
/// `u` (microseconds), `n` (nanoseconds).
pub(crate) fn parse_grpc_timeout(value: &str) -> Option<std::time::Duration> {
	if value.len() < 2 {
		return None;
	}
	let (num_str, unit) = value.split_at(value.len() - 1);
	let num: u64 = num_str.parse().ok()?;
	match unit {
		"H" => Some(std::time::Duration::from_secs(num * 3600)),
		"M" => Some(std::time::Duration::from_secs(num * 60)),
		"S" => Some(std::time::Duration::from_secs(num)),
		"m" => Some(std::time::Duration::from_millis(num)),
		"u" => Some(std::time::Duration::from_micros(num)),
		"n" => Some(std::time::Duration::from_nanos(num)),
		_ => None,
	}
}

/// Retrieve a gRPC metadata value from request headers.
///
/// Per the gRPC spec, headers ending in `-bin` contain base64-encoded binary data.
/// All other metadata values are returned as raw UTF-8 bytes.
#[allow(dead_code)] // Available for handlers that need to read binary gRPC metadata
pub(crate) fn get_grpc_metadata(headers: &HeaderMap, key: &str) -> Option<Vec<u8>> {
	let value = headers.get(key)?;
	if key.ends_with("-bin") {
		base64::engine::general_purpose::STANDARD.decode(value.as_bytes()).ok()
	} else {
		value.to_str().ok().map(|s| s.as_bytes().to_vec())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_encode_decode_roundtrip() {
		let payload = b"hello world";
		let encoded = encode_grpc_frame(payload);
		let decoded = decode_grpc_body(&encoded).unwrap();
		assert_eq!(decoded, payload);
	}

	#[test]
	fn test_encode_empty() {
		let encoded = encode_grpc_frame(b"");
		assert_eq!(encoded.len(), 5);
		assert_eq!(&encoded[..5], &[0, 0, 0, 0, 0]);
		let decoded = decode_grpc_body(&encoded).unwrap();
		assert!(decoded.is_empty());
	}

	#[test]
	fn test_decode_too_short() {
		assert!(decode_grpc_body(&[0, 0, 0]).is_err());
	}

	#[test]
	fn test_decode_compressed_rejected() {
		let data = vec![1u8, 0, 0, 0, 1, 42]; // compressed flag = 1
		let result = decode_grpc_body(&data);
		assert!(result.is_err());
		assert_eq!(result.unwrap_err().code, GRPC_STATUS_UNIMPLEMENTED);
	}

	#[test]
	fn test_decode_length_exceeds_body() {
		let data = vec![0u8, 0, 0, 0, 10, 1, 2]; // claims 10 bytes, only 2 present
		let result = decode_grpc_body(&data);
		assert!(result.is_err());
		assert_eq!(result.unwrap_err().code, GRPC_STATUS_INVALID_ARGUMENT);
	}

	#[test]
	fn test_percent_encode() {
		assert_eq!(percent_encode("hello"), "hello");
		assert_eq!(percent_encode("a/b"), "a%2Fb");
		assert_eq!(percent_encode("100%"), "100%25");
	}

	#[test]
	fn test_error_to_grpc_status() {
		let e = LdkServerError::new(LdkServerErrorCode::AuthError, "bad auth");
		let s = ldk_error_to_grpc_status(e);
		assert_eq!(s.code, GRPC_STATUS_UNAUTHENTICATED);
		assert_eq!(s.message, "bad auth");
	}

	#[test]
	fn test_decode_trailing_data_rejected() {
		let data = vec![0u8, 0, 0, 0, 1, 42, 99]; // 1-byte payload + trailing byte
		let result = decode_grpc_body(&data);
		assert!(result.is_err());
		assert_eq!(result.unwrap_err().code, GRPC_STATUS_INVALID_ARGUMENT);
	}

	#[test]
	fn test_get_grpc_metadata_text() {
		let mut headers = hyper::http::HeaderMap::new();
		headers.insert("x-custom", HeaderValue::from_static("hello"));
		assert_eq!(get_grpc_metadata(&headers, "x-custom"), Some(b"hello".to_vec()));
	}

	#[test]
	fn test_get_grpc_metadata_binary() {
		let mut headers = hyper::http::HeaderMap::new();
		// base64("hello") = "aGVsbG8="
		headers.insert("x-custom-bin", HeaderValue::from_static("aGVsbG8="));
		assert_eq!(get_grpc_metadata(&headers, "x-custom-bin"), Some(b"hello".to_vec()));
	}

	#[test]
	fn test_get_grpc_metadata_missing() {
		let headers = hyper::http::HeaderMap::new();
		assert_eq!(get_grpc_metadata(&headers, "x-missing"), None);
	}

	#[test]
	fn test_parse_grpc_timeout() {
		use std::time::Duration;
		assert_eq!(parse_grpc_timeout("5S"), Some(Duration::from_secs(5)));
		assert_eq!(parse_grpc_timeout("500m"), Some(Duration::from_millis(500)));
		assert_eq!(parse_grpc_timeout("1H"), Some(Duration::from_secs(3600)));
		assert_eq!(parse_grpc_timeout("30M"), Some(Duration::from_secs(1800)));
		assert_eq!(parse_grpc_timeout("100u"), Some(Duration::from_micros(100)));
		assert_eq!(parse_grpc_timeout("1000n"), Some(Duration::from_nanos(1000)));
		assert_eq!(parse_grpc_timeout(""), None);
		assert_eq!(parse_grpc_timeout("S"), None);
		assert_eq!(parse_grpc_timeout("5x"), None);
	}
}
