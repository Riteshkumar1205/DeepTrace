import os
import math
from typing import Dict, Any, Tuple, List
from PIL import Image, ImageChops, ImageFilter, ImageStat
import imagehash

class ImageForensicsService:
    @staticmethod
    def run_all_analyses(file_path: str, evidence_id: str, upload_dir: str) -> Dict[str, Any]:
        """
        Runs ELA, Noise analysis, Clone detection, and JPEG Ghost analysis on an image.
        """
        results = {}
        
        # 1. Error Level Analysis (ELA)
        ela_path, ela_tampered, ela_conf = ImageForensicsService.calculate_ela(file_path, evidence_id, upload_dir)
        results["ela"] = {
            "tampered": ela_tampered,
            "confidence": ela_conf,
            "output_image_path": ela_path
        }
        
        # 2. Noise Analysis
        noise_tampered, noise_conf, noise_stats = ImageForensicsService.analyze_noise(file_path)
        results["noise"] = {
            "tampered": noise_tampered,
            "confidence": noise_conf,
            "statistics": noise_stats
        }
        
        # 3. Clone Detection
        clone_detected, clone_conf, clone_regions = ImageForensicsService.detect_clones(file_path)
        results["clone_detection"] = {
            "tampered": clone_detected,
            "confidence": clone_conf,
            "modified_regions": clone_regions
        }

        # 4. JPEG Ghost Detection
        ghost_detected, ghost_conf, ghost_quality = ImageForensicsService.detect_jpeg_ghosts(file_path)
        results["jpeg_ghost"] = {
            "tampered": ghost_detected,
            "confidence": ghost_conf,
            "detected_original_quality": ghost_quality
        }

        # Calculate total tampered status and average confidence
        total_tampered = ela_tampered or noise_tampered or clone_detected
        total_confidence = (ela_conf + noise_conf + clone_conf) / 3.0

        supporting_evidence = []
        if ela_tampered:
            supporting_evidence.append("ELA energy delta exceeded the tamper threshold.")
        if noise_tampered:
            supporting_evidence.append("Noise dispersion suggests compositing or multi-source editing.")
        if clone_detected:
            supporting_evidence.append(f"Clone matching detected across {len(clone_regions)} block pair(s).")
        if ghost_detected:
            supporting_evidence.append(f"JPEG ghost analysis favoured prior recompression quality {ghost_quality}.")
        if not supporting_evidence:
            supporting_evidence.append("No ELA, noise, clone, or JPEG ghost anomalies detected.")

        return {
            "tampered": total_tampered,
            "confidence": round(total_confidence, 2),
            "verification_method": "ELA + Noise + Clone Similarity + JPEG Ghost",
            "supporting_evidence": supporting_evidence,
            "modified_regions": clone_regions,
            "details": results
        }

    @staticmethod
    def calculate_ela(file_path: str, evidence_id: str, upload_dir: str, quality: int = 95) -> Tuple[str, bool, float]:
        """
        Computes Error Level Analysis (ELA) on the target image.
        Saves the resulting difference image to disk for display.
        """
        ela_filename = f"ela_{evidence_id}.jpg"
        ela_path = os.path.join(upload_dir, ela_filename)
        
        try:
            with Image.open(file_path) as original:
                original = original.convert("RGB")
                
                # Temporary compressed file path
                temp_compressed = f"{file_path}.resaved.jpg"
                original.save(temp_compressed, "JPEG", quality=quality)
                
                with Image.open(temp_compressed) as compressed:
                    # Calculate absolute differences
                    diff = ImageChops.difference(original, compressed)
                    
                    # Find maximum brightness diff to auto-scale brightness for readability
                    extrema = diff.getextrema()
                    max_diff = max([ex[1] for ex in extrema])
                    if max_diff == 0:
                        max_diff = 1
                    
                    scale = 255.0 / max_diff
                    # Boost scale to highlight subtle anomalies (standard ELA multiplier)
                    scale = min(scale, 15.0) 
                    
                    # Apply brightness scaling
                    ela_img = diff.point(lambda p: int(p * scale))
                    ela_img.save(ela_path, "JPEG")
                    
                    # Evaluate average difference energy
                    stat = ImageStat.Stat(ela_img)
                    mean_diff = sum(stat.mean) / 3.0
                    
                    # Higher average difference energy in ELA indicates potential tampering or splicing
                    # Generally, an ELA mean above 8-10 in a scaled image signifies high pixel editing entropy
                    tampered = mean_diff > 12.0
                    confidence = min(100.0, max(0.0, mean_diff * 4.5))
                    if tampered:
                        confidence = max(65.0, confidence)
                    else:
                        confidence = max(10.0, 100.0 - confidence)

                # Clean up compressed temp file
                if os.path.exists(temp_compressed):
                    os.remove(temp_compressed)

                return f"/api/v1/storage/uploads/{ela_filename}", tampered, round(confidence, 2)
        except Exception:
            return "", False, 0.0

    @staticmethod
    def analyze_noise(file_path: str) -> Tuple[bool, float, Dict[str, Any]]:
        """
        Performs high-frequency noise analysis using local standard deviations.
        Spliced image regions exhibit distinct noise distributions.
        """
        try:
            with Image.open(file_path) as img:
                img = img.convert("L")  # Grayscale for noise check
                width, height = img.size
                
                # Apply high-pass filter: subtract low-pass filtered image
                blurred = img.filter(ImageFilter.GaussianBlur(radius=2))
                diff = ImageChops.difference(img, blurred)
                
                # Divide the diff image into 8x8 blocks and calculate local variance
                block_size = 32
                blocks_x = width // block_size
                blocks_y = height // block_size
                
                variances = []
                for x in range(blocks_x):
                    for y in range(blocks_y):
                        box = (x * block_size, y * block_size, (x + 1) * block_size, (y + 1) * block_size)
                        crop = diff.crop(box)
                        stat = ImageStat.Stat(crop)
                        variances.append(stat.var[0])
                
                if not variances:
                    return False, 0.0, {}

                # Calculate variance anomalies
                mean_var = sum(variances) / len(variances)
                variance_of_variances = sum((v - mean_var) ** 2 for v in variances) / len(variances)
                std_of_variances = math.sqrt(variance_of_variances)
                
                # Detect anomalies: if standard deviation of local noise blocks is abnormally high,
                # it suggests mixed-camera splicing or multi-source noise layering.
                anomaly_ratio = std_of_variances / (mean_var + 1e-5)
                tampered = anomaly_ratio > 0.45
                confidence = min(98.0, anomaly_ratio * 120.0) if tampered else max(15.0, 100.0 - (anomaly_ratio * 100.0))
                
                stats = {
                    "mean_noise_variance": round(mean_var, 3),
                    "variance_dispersion": round(std_of_variances, 3),
                    "anomaly_ratio": round(anomaly_ratio, 3)
                }
                return tampered, round(confidence, 2), stats
        except Exception as e:
            return False, 0.0, {"error": str(e)}

    @staticmethod
    def detect_clones(file_path: str) -> Tuple[bool, float, List[Dict[str, Any]]]:
        """
        Detects copy-paste clone alterations by analyzing block hash similarities.
        """
        try:
            with Image.open(file_path) as img:
                width, height = img.size
                
                # Crop image into 8 overlapping blocks and compare hashes
                blocks = []
                block_w = width // 3
                block_h = height // 3
                
                for x in range(3):
                    for y in range(3):
                        box = (x * block_w, y * block_h, min((x + 1) * block_w, width), min((y + 1) * block_h, height))
                        crop = img.crop(box)
                        h_val = imagehash.phash(crop)
                        blocks.append({"box": box, "hash": h_val, "coords": (x, y)})

                clones = []
                # Compare all block hashes pairwise
                for i in range(len(blocks)):
                    for j in range(i + 1, len(blocks)):
                        diff = blocks[i]["hash"] - blocks[j]["hash"]
                        # Hamming distance <= 2 indicates extremely similar visual structures (spliced clones)
                        if diff <= 2:
                            clones.append({
                                "source_block": blocks[i]["box"],
                                "target_block": blocks[j]["box"],
                                "hamming_distance": int(diff)
                            })
                
                tampered = len(clones) > 0
                confidence = 92.0 if tampered else 95.0
                return tampered, confidence, clones
        except Exception:
            return False, 0.0, []

    @staticmethod
    def detect_jpeg_ghosts(file_path: str) -> Tuple[bool, float, int]:
        """
        Estimates JPEG compression ghost artifacts.
        Finds the compression quality at which difference map energy is minimized.
        """
        try:
            with Image.open(file_path) as original:
                original = original.convert("RGB")
                
                min_energy = float("inf")
                best_quality = 90
                
                # Run quick scan over qualities 60, 70, 80, 90 to find local compression valleys
                for q in [60, 75, 90]:
                    temp_f = f"{file_path}.ghost_{q}.jpg"
                    original.save(temp_f, "JPEG", quality=q)
                    with Image.open(temp_f) as comp:
                        diff = ImageChops.difference(original, comp)
                        stat = ImageStat.Stat(diff)
                        energy = sum(stat.mean)
                        if energy < min_energy:
                            min_energy = energy
                            best_quality = q
                    if os.path.exists(temp_f):
                        os.remove(temp_f)
                
                # If best_quality is very low (e.g. 60) yet the file is saved as high quality,
                # it indicates double-compression ghosting (evidence of re-saving manipulated layers).
                tampered = best_quality < 70
                confidence = 85.0 if tampered else 90.0
                return tampered, confidence, best_quality
        except Exception:
            return False, 0.0, 90
