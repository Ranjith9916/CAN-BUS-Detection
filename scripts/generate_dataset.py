"""
Synthetic CAN dataset generator for ML training.

Generates labeled traffic windows with NORMAL and various attack types.
Uses fixed random seeds for reproducibility. Avoids data leakage by
generating separate sequences for train/test splits.
"""

from __future__ import annotations

import csv
import logging
import os
import time
from pathlib import Path
from typing import Any

import numpy as np

from can_security.attacks.simulator import AttackSimulator
from can_security.can.simulator import VehicleSimulator
from can_security.core.config import AppConfig, load_config
from can_security.core.enums import AttackType
from can_security.core.models import CANMessage
from can_security.features.extractor import FeatureExtractor

logger = logging.getLogger(__name__)


def generate_dataset(
    config: AppConfig,
    output_dir: str = "ml/datasets",
    duration_per_class: float = 30.0,
    window_size: int = 100,
    seed: int = 42,
) -> dict[str, Any]:
    """
    Generate a labeled CAN dataset for ML training.

    Produces separate sequences per class and per split to avoid leakage.
    Each sequence is an independent simulation run with different seeds.

    Returns metadata about the generated dataset.
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    feature_names = FeatureExtractor.feature_names()
    rng = np.random.RandomState(seed)

    attack_configs = [
        (AttackType.NONE, {"label": "NORMAL"}),
        (AttackType.FLOODING, {"rate": 20, "target_id": 0x102}),
        (AttackType.INJECTION, {"injected_id": 0x7FF}),
        (AttackType.REPLAY, {"stale_counter": 1, "target_id": 0x100}),
        (AttackType.SPOOFING, {"target_id": 0x102}),
        (AttackType.ABNORMAL_FREQUENCY, {"rate": 8, "target_id": 0x103}),
    ]

    all_samples: list[dict[str, Any]] = []

    for attack_type, attack_kwargs in attack_configs:
        class_name = attack_type.value if attack_type != AttackType.NONE else "NORMAL"
        logger.info(f"Generating {class_name} traffic...")

        # Two independent simulation runs: one for train, one for test
        for split_idx, split_name in enumerate(["train", "test"]):
            split_seed = seed + hash(class_name) + split_idx * 1000
            config.simulation.seed = abs(split_seed) % (2**31)

            samples = _generate_class_samples(
                config=config,
                attack_type=attack_type,
                attack_kwargs=attack_kwargs,
                duration=duration_per_class * (0.8 if split_name == "train" else 0.2),
                window_size=window_size,
                feature_names=feature_names,
                split=split_name,
            )
            all_samples.extend(samples)

        logger.info(f"  {class_name}: generated samples")

    # Shuffle within splits
    train_samples = [s for s in all_samples if s["split"] == "train"]
    test_samples = [s for s in all_samples if s["split"] == "test"]
    rng.shuffle(train_samples)
    rng.shuffle(test_samples)

    # Write CSV files
    header = feature_names + ["label", "split"]

    train_path = output_path / "train.csv"
    _write_csv(train_path, header, train_samples, feature_names)

    test_path = output_path / "test.csv"
    _write_csv(test_path, header, test_samples, feature_names)

    # Write combined
    all_path = output_path / "dataset.csv"
    _write_csv(all_path, header, train_samples + test_samples, feature_names)

    # Stats
    stats = {
        "total_samples": len(all_samples),
        "train_samples": len(train_samples),
        "test_samples": len(test_samples),
        "features": len(feature_names),
        "classes": list({s["label"] for s in all_samples}),
        "class_distribution": {},
        "output_dir": str(output_path),
    }
    for s in all_samples:
        label = s["label"]
        stats["class_distribution"][label] = stats["class_distribution"].get(label, 0) + 1

    logger.info(f"Dataset generated: {stats['total_samples']} samples, {len(feature_names)} features")
    return stats


def _generate_class_samples(
    config: AppConfig,
    attack_type: AttackType,
    attack_kwargs: dict[str, Any],
    duration: float,
    window_size: int,
    feature_names: list[str],
    split: str,
) -> list[dict[str, Any]]:
    """Generate feature vectors for a single class."""
    simulator = VehicleSimulator(config)
    simulator.start()

    attacker = AttackSimulator(seed=config.simulation.seed + 999)
    extractor = FeatureExtractor(window_size=window_size, window_overlap=window_size // 2)

    # Start attack after a short warm-up
    is_attack = attack_type != AttackType.NONE
    attack_start_time = 1.0  # Start attack after 1s warm-up

    if is_attack:
        target = attack_kwargs.get("target_id", 0x102)
        kwargs_copy = {k: v for k, v in attack_kwargs.items() if k != "target_id"}

    tick_dt = 1.0 / config.simulation.tick_rate_hz
    sim_time = 0.0
    samples: list[dict[str, Any]] = []

    while sim_time < duration:
        # Generate normal traffic
        messages = simulator.tick(sim_time, tick_dt)

        # Inject attack traffic after warm-up
        if is_attack and sim_time >= attack_start_time:
            if not attacker.is_running:
                attacker.start_attack(attack_type, target_id=target, **kwargs_copy)
            attack_msgs = attacker.generate_attack_messages(sim_time)
            messages.extend(attack_msgs)

        # Feed to feature extractor
        for msg in messages:
            label = attack_type if is_attack and sim_time >= attack_start_time else AttackType.NONE
            fv = extractor.add_message(msg)
            if fv is not None:
                sample = {feat: fv.features.get(feat, 0.0) for feat in feature_names}
                sample["label"] = label.value if label != AttackType.NONE else "NORMAL"
                sample["split"] = split
                samples.append(sample)

        sim_time += tick_dt

    simulator.stop()
    if attacker.is_running:
        attacker.stop_attack()

    return samples


def _write_csv(
    path: Path,
    header: list[str],
    samples: list[dict[str, Any]],
    feature_names: list[str],
) -> None:
    """Write samples to CSV."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for sample in samples:
            row = [sample.get(feat, 0.0) for feat in feature_names]
            row.append(sample["label"])
            row.append(sample["split"])
            writer.writerow(row)
