import Foundation

/// Backports of URLSession async APIs for iOS 14 compatibility.
extension URLSession {
    func kiskisData(for request: URLRequest) async throws -> (Data, URLResponse) {
        if #available(iOS 15.0, macOS 12.0, *) {
            return try await self.data(for: request)
        } else {
            return try await withCheckedThrowingContinuation { continuation in
                let task = self.dataTask(with: request) { data, response, error in
                    if let error = error {
                        continuation.resume(throwing: error)
                    } else if let data = data, let response = response {
                        continuation.resume(returning: (data, response))
                    } else {
                        continuation.resume(throwing: KiskisError.networkError("No data or response"))
                    }
                }
                task.resume()
            }
        }
    }

    func kiskisDownload(from url: URL) async throws -> (URL, URLResponse) {
        if #available(iOS 15.0, macOS 12.0, *) {
            return try await self.download(from: url)
        } else {
            return try await withCheckedThrowingContinuation { continuation in
                let task = self.downloadTask(with: url) { localURL, response, error in
                    if let error = error {
                        continuation.resume(throwing: error)
                    } else if let localURL = localURL, let response = response {
                        // Copy to a temp file that won't be auto-deleted
                        let tempDir = FileManager.default.temporaryDirectory
                        let tempFile = tempDir.appendingPathComponent(UUID().uuidString)
                        do {
                            try FileManager.default.copyItem(at: localURL, to: tempFile)
                            continuation.resume(returning: (tempFile, response))
                        } catch {
                            continuation.resume(throwing: error)
                        }
                    } else {
                        continuation.resume(throwing: KiskisError.networkError("Download failed"))
                    }
                }
                task.resume()
            }
        }
    }
}
