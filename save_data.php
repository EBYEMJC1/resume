<?php
// Set the content type of the response to JSON
header('Content-Type: application/json');

// --- 1. Basic Security: Only accept POST requests ---
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    // If it's not a POST request, send an error and stop execution.
    http_response_code(405); // Method Not Allowed
    echo json_encode(['success' => false, 'message' => 'Error: This endpoint only accepts POST requests.']);
    exit;
}

// --- 2. Get and Decode the Incoming JSON Data ---
// Get the raw JSON payload from the request body
$json_input = file_get_contents('php://input');
// Decode the JSON string into a PHP associative array
$data = json_decode($json_input, true);

// Check if JSON decoding was successful and if the required keys exist
if ($data === null || !isset($data['filename']) || !isset($data['jsonData'])) {
    http_response_code(400); // Bad Request
    echo json_encode(['success' => false, 'message' => 'Error: Invalid or incomplete JSON payload.']);
    exit;
}

// --- 3. Validate the Filename for Security ---
$filename = $data['filename'];

// IMPORTANT: This regex is a security measure to prevent "path traversal" attacks.
// It ensures the filename only contains letters, numbers, hyphens, and ends with ".json".
// This prevents a malicious user from trying to write to files outside the intended directory (e.g., "../../../etc/passwd").
if (!preg_match('/^[a-z0-9\-]+\.json$/', $filename)) {
    http_response_code(400); // Bad Request
    echo json_encode(['success' => false, 'message' => 'Error: Invalid filename format.']);
    exit;
}

// At this point, the filename is considered safe to use.
$filePath = __DIR__ . '/' . $filename; // Use __DIR__ to ensure the path is relative to this script's location.

// --- 4. Write the Data to the File ---
$jsonData = $data['jsonData'];

// Use file_put_contents to write the data. This is an atomic operation (it creates/replaces the file).
// The function returns the number of bytes written, or false on failure.
if (file_put_contents($filePath, $jsonData) !== false) {
    // If writing was successful, send back a success response.
    echo json_encode(['success' => true, 'message' => "File '$filename' saved successfully."]);
} else {
    // If writing failed, send back an error response.
    http_response_code(500); // Internal Server Error
    echo json_encode(['success' => false, 'message' => "Error: Could not write to file '$filename'. Check server permissions."]);
}

?>
