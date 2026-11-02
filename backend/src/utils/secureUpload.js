const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');

/**
 * Secure profile-picture upload handling, shared by student and teacher
 * picture endpoints (routes/profiles.js, routes/admin.js).
 *
 * Security properties this module is responsible for:
 *  - Only real JPEG/PNG files are accepted — validated by inspecting the
 *    first bytes of the actual file content (magic numbers), never by
 *    trusting the client-supplied filename extension or MIME type. A
 *    renamed .php or .svg file will be rejected here even if the client
 *    lies about its Content-Type or names it "photo.jpg".
 *  - Stored filenames are always fully server-generated
 *    (crypto.randomBytes hex + a fixed extension WE chose based on the
 *    detected type) — the client's original filename is never used for
 *    anything, including display, so there is no path-traversal surface
 *    and no way to overwrite an arbitrary file by controlling the name.
 *  - A hard size cap (multer's `limits.fileSize`) rejects oversized
 *    uploads before the full body is even buffered.
 *  - Files are written under a single fixed directory
 *    (UPLOAD_DIR below); nothing in this module ever joins a path using
 *    unsanitized input, so there is no way to escape that directory.
 */

const UPLOAD_DIR = path.join(__dirname, '..', '..', 'uploads', 'profile-pictures');
const MAX_FILE_SIZE = 2 * 1024 * 1024; // 2MB — generous for a headshot, small enough to prevent abuse

// Signature (magic number) checks — first bytes only, independent of
// filename/extension/declared Content-Type.
const SIGNATURES = [
  { ext: 'jpg', mime: 'image/jpeg', check: (b) => b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  {
    ext: 'png', mime: 'image/png',
    check: (b) => b.length >= 8 &&
      b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47 &&
      b[4] === 0x0d && b[5] === 0x0a && b[6] === 0x1a && b[7] === 0x0a
  }
];

function ensureUploadDir() {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

/** Returns the matching signature entry for a buffer, or null if it isn't
 * a recognized JPEG/PNG — regardless of what the upload claimed to be. */
function detectImageType(buffer) {
  return SIGNATURES.find((sig) => sig.check(buffer)) || null;
}

// multer with memoryStorage: buffers the file in memory only long enough
// for us to check its real magic bytes before ever writing to disk —
// nothing with an unrecognized signature is ever saved.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_SIZE, files: 1 }
}).single('picture');

/**
 * Validates req.file's actual content and, if it's a real JPEG/PNG,
 * writes it to disk under a fresh random filename. Returns the stored
 * filename (not a path) on success, or throws an Error with a
 * user-safe .message on rejection.
 */
function saveValidatedImage(fileBuffer) {
  if (!fileBuffer || !fileBuffer.length) {
    throw new Error('No file was uploaded.');
  }
  const sig = detectImageType(fileBuffer);
  if (!sig) {
    throw new Error('Only JPG and PNG image files are allowed.');
  }
  ensureUploadDir();
  const filename = `${crypto.randomBytes(24).toString('hex')}.${sig.ext}`;
  fs.writeFileSync(path.join(UPLOAD_DIR, filename), fileBuffer);
  return filename;
}

/** Deletes a previously-stored picture file by its stored filename.
 * Filenames are always our own crypto.randomBytes output (see above), so
 * this never receives attacker-controlled input in practice — still,
 * basename() strips any path segments defensively before use. */
function deleteStoredImage(filename) {
  if (!filename) return;
  const safeName = path.basename(String(filename));
  const filePath = path.join(UPLOAD_DIR, safeName);
  try {
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  } catch (err) {
    console.error('[secureUpload] Could not delete', safeName, err.message);
  }
}

module.exports = { upload, saveValidatedImage, deleteStoredImage, UPLOAD_DIR, MAX_FILE_SIZE };
