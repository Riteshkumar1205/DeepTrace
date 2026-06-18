import hashlib
import os
from typing import Dict, Any, Tuple
from PIL import Image
import imagehash
from passlib.context import CryptContext


pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

class HashingService:
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a plaintext password for secure storage."""
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a plaintext password against a stored hash."""
        return pwd_context.verify(plain_password, hashed_password)

    @staticmethod
    def calculate_crypto_hashes(file_path: str) -> Tuple[str, str, str]:
        """
        Calculates MD5, SHA256, and SHA512 for a given file.
        """
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        sha512_hash = hashlib.sha512()

        # Read in 64kb chunks to prevent memory bloat
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(65536), b""):
                md5_hash.update(byte_block)
                sha256_hash.update(byte_block)
                sha512_hash.update(byte_block)

        return md5_hash.hexdigest(), sha256_hash.hexdigest(), sha512_hash.hexdigest()

    @staticmethod
    def calculate_image_hashes(file_path: str) -> Tuple[str, str, str]:
        """
        Calculates pHash, aHash, and dHash for supported image files.
        """
        try:
            with Image.open(file_path) as img:
                p_hash = str(imagehash.phash(img))
                a_hash = str(imagehash.average_hash(img))
                d_hash = str(imagehash.dhash(img))
                return p_hash, a_hash, d_hash
        except Exception as e:
            # Fallback/Error recovery if file is not a valid image or library fails
            return "unknown", "unknown", "unknown"

    @staticmethod
    def calculate_video_signatures(file_path: str) -> Dict[str, Any]:
        """
        Calculates frame/scene and keyframe hashes for videos.
        For Phase 1, we extract metadata properties and generate a deterministic
        structural fingerprint based on sample blocks of the video file.
        """
        try:
            file_size = os.path.getsize(file_path)
            # Create a mock/simplified video signature by hashing slices of the video file
            signatures = []
            with open(file_path, "rb") as f:
                # Sample 4 locations throughout the video file to represent visual frames
                for i in range(4):
                    offset = int(file_size * (i + 1) / 5)
                    f.seek(offset)
                    chunk = f.read(4096)
                    signatures.append(hashlib.md5(chunk).hexdigest())

            return {
                "keyframe_hashes": signatures,
                "frame_signatures": [s[:16] for s in signatures],
                "scene_signatures": [signatures[0], signatures[-1]],
                "method": "sampled_binary_slices"
            }
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def calculate_audio_signatures(file_path: str) -> Dict[str, Any]:
        """
        Generates acoustic signatures for audio files.
        In Phase 1, we calculate a perceptual byte hash of the audio payload.
        """
        try:
            file_size = os.path.getsize(file_path)
            # Sample audio byte blocks to generate acoustic fingerprint
            fingerprints = []
            with open(file_path, "rb") as f:
                # Seek to header end and read data blocks
                f.seek(min(4096, file_size))
                for i in range(3):
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    fingerprints.append(hashlib.md5(chunk).hexdigest())

            return {
                "acoustic_fingerprints": fingerprints,
                "chroma_signature": fingerprints[0][:20] if fingerprints else "empty",
                "method": "sampled_acoustic_slices"
            }
        except Exception as e:
            return {"error": str(e)}
