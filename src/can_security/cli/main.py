"""
CLI entry point for the CAN Security Framework.

Provides commands for running simulations, training models,
evaluating detectors, launching attacks, and benchmarking.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from can_security.core.config import load_config

console = Console()


def setup_logging(level: str = "INFO") -> None:
    """Configure structured logging."""
    log_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


@click.group()
@click.option("--config-dir", default=None, help="Path to config directory")
@click.option("--log-level", default="INFO", help="Logging level")
@click.pass_context
def cli(ctx: click.Context, config_dir: str | None, log_level: str) -> None:
    """
    CAN Security Framework -- Intrusion Detection & Message Authentication

    [SIMULATION MODE] -- Research/Laboratory Use Only
    """
    ctx.ensure_object(dict)
    setup_logging(log_level)
    try:
        config = load_config(config_dir)
        ctx.obj["config"] = config
    except Exception as e:
        console.print(f"[red]Configuration error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.pass_context
def health(ctx: click.Context) -> None:
    """Check system health and configuration."""
    config = ctx.obj["config"]

    table = Table(title="🔧 System Health Check")
    table.add_column("Component", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Details")

    table.add_row("Configuration", "✅ Loaded", f"Mode: {config.mode}")
    table.add_row("CAN Interface", "✅ Ready", f"Type: {config.can.interface}")
    table.add_row(
        "CAN IDs", "✅ Loaded", f"{len(config.can_id_definitions)} IDs defined"
    )
    table.add_row(
        "Detection Rules",
        "✅ Loaded",
        f"{len(config.detection_rules)} rules",
    )
    table.add_row(
        "Authentication",
        "✅ Configured" if config.authentication.enabled else "⚠️ Disabled",
        config.authentication.algorithm,
    )
    table.add_row("Database", "✅ Configured", config.database.url)
    table.add_row("ML Model", "ℹ️ Pending", config.ml.model_type)

    console.print(table)
    console.print(
        Panel(
            "[yellow]⚠️  SIMULATION MODE — This is a research prototype.\n"
            "Do NOT connect to real vehicle systems.[/yellow]",
            title="Safety Notice",
            border_style="yellow",
        )
    )


@cli.command()
@click.option("--duration", default=10, help="Simulation duration in seconds")
@click.option("--seed", default=None, type=int, help="Random seed for reproducibility")
@click.pass_context
def simulate(ctx: click.Context, duration: int, seed: int | None) -> None:
    """Run the vehicle CAN bus simulation."""
    config = ctx.obj["config"]
    if seed is not None:
        config.simulation.seed = seed

    from can_security.can.simulator import VehicleSimulator

    console.print(
        Panel(
            "[cyan]Starting CAN Bus Vehicle Simulation[/cyan]\n"
            f"Duration: {duration}s | Seed: {config.simulation.seed}",
            title="🚗 Vehicle Simulator",
        )
    )

    simulator = VehicleSimulator(config)
    simulator.start()

    tick_dt = 1.0 / config.simulation.tick_rate_hz
    sim_time = 0.0
    total_msgs = 0
    id_counts: dict[str, int] = {}

    start_real = time.time()

    try:
        while sim_time < duration:
            messages = simulator.tick(sim_time, tick_dt)
            total_msgs += len(messages)
            for msg in messages:
                hex_id = msg.can_id_hex
                id_counts[hex_id] = id_counts.get(hex_id, 0) + 1

            sim_time += tick_dt

            # Progress update every second
            if int(sim_time) > int(sim_time - tick_dt) and int(sim_time) % 2 == 0:
                elapsed = time.time() - start_real
                state = simulator.vehicle_state
                console.print(
                    f"  t={sim_time:.0f}s | "
                    f"Speed={state.get('speed', 0):.1f} km/h | "
                    f"Phase={simulator._scenario_phase} | "
                    f"Messages={total_msgs} | "
                    f"Rate={total_msgs / elapsed:.0f} msg/s"
                )

    except KeyboardInterrupt:
        console.print("\n[yellow]Simulation interrupted.[/yellow]")

    simulator.stop()
    elapsed = time.time() - start_real

    # Results table
    table = Table(title="📊 Simulation Results")
    table.add_column("CAN ID", style="cyan")
    table.add_column("Messages", justify="right")
    table.add_column("Rate (msg/s)", justify="right")

    for hex_id, count in sorted(id_counts.items()):
        rate = count / elapsed if elapsed > 0 else 0
        table.add_row(hex_id, str(count), f"{rate:.1f}")

    table.add_row("TOTAL", str(total_msgs), f"{total_msgs / elapsed:.1f}", style="bold")

    console.print(table)
    console.print(f"[green]✅ Simulation complete in {elapsed:.2f}s[/green]")


@cli.command()
@click.pass_context
def demo(ctx: click.Context) -> None:
    """Run the complete demonstration with attack scenarios."""
    console.print(
        Panel(
            "[bold cyan]CAN Security Framework — Full Demonstration[/bold cyan]\n"
            "[yellow]⚠️  SIMULATION MODE[/yellow]",
            title="🎯 Demo Mode",
        )
    )
    console.print("[dim]Demo mode will be fully implemented in Phase 17.[/dim]")
    # Placeholder — will be implemented with full pipeline integration
    ctx.invoke(simulate, duration=5)


@cli.command()
@click.pass_context
def train(ctx: click.Context) -> None:
    """Train the ML intrusion detection model."""
    config = ctx.obj["config"]
    console.print("[cyan]Training ML model...[/cyan]")

    from scripts.train_model import train_and_evaluate
    results = train_and_evaluate(
        n_estimators=config.ml.n_estimators,
        max_depth=config.ml.max_depth,
        seed=config.ml.random_seed,
    )
    console.print(f"[green]Training complete! F1={results['f1_score']:.4f}[/green]")


@cli.command()
@click.pass_context
def evaluate(ctx: click.Context) -> None:
    """Evaluate the ML model performance."""
    console.print("[cyan]Evaluating model...[/cyan]")
    from scripts.train_model import train_and_evaluate
    train_and_evaluate()


@cli.command()
@click.option("--type", "attack_type", default="flooding", help="Attack type")
@click.option("--target", default="0x102", help="Target CAN ID")
@click.option("--duration", default=5, help="Attack duration in seconds")
@click.pass_context
def attack(ctx: click.Context, attack_type: str, target: str, duration: int) -> None:
    """Launch a simulated attack (SIMULATION MODE ONLY)."""
    console.print("[dim]Attack simulation will be implemented in Phase 13.[/dim]")


@cli.command()
@click.pass_context
def benchmark(ctx: click.Context) -> None:
    """Run performance benchmarks."""
    console.print("[dim]Benchmarking will be implemented in Phase 19.[/dim]")


@cli.command(name="generate-dataset")
@click.option("--duration", default=30, help="Duration per class in seconds")
@click.option("--output", default="ml/datasets/", help="Output directory")
@click.pass_context
def generate_dataset(ctx: click.Context, duration: int, output: str) -> None:
    """Generate synthetic CAN dataset for ML training."""
    config = ctx.obj["config"]
    console.print("[cyan]Generating dataset...[/cyan]")

    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent))
    from scripts.generate_dataset import generate_dataset as gen

    stats = gen(
        config=config,
        output_dir=output,
        duration_per_class=duration,
        window_size=config.feature_extraction.window_size,
        seed=config.simulation.seed,
    )
    console.print(f"[green]Dataset generated: {stats['total_samples']} samples[/green]")
    for cls, count in sorted(stats['class_distribution'].items()):
        console.print(f"  {cls}: {count}")


@cli.command()
@click.pass_context
def start(ctx: click.Context) -> None:
    """Start the FastAPI backend server."""
    import uvicorn
    config = ctx.obj["config"]
    console.print("[cyan]Starting API server...[/cyan]")
    uvicorn.run(
        "can_security.api.main:app",
        host=config.api.host,
        port=config.api.port,
        reload=False,
    )


@cli.command(name="busmaster-simulate")
@click.option("--duration", default=10, help="Simulation duration in seconds")
@click.option("--export-log", default=None, help="File path to save BUSMASTER .log trace")
@click.option("--bus-speed", default=500000, help="CAN bus bitrate (bps)")
@click.pass_context
def busmaster_simulate(ctx: click.Context, duration: int, export_log: str | None, bus_speed: int) -> None:
    """Run the BUSMASTER-compatible CAN bus simulator with virtual ECUs."""
    from can_security.can.busmaster import BusmasterSimulator

    console.print(
        Panel(
            f"[bold cyan]BUSMASTER CAN Bus Network Simulator[/bold cyan]\n"
            f"Duration: {duration}s | Bus Speed: {bus_speed} bps | Mode: Multi-Node Simulation",
            title="[BUSMASTER Simulation Engine]",
            border_style="cyan",
        )
    )

    sim = BusmasterSimulator(bus_speed=bus_speed)
    sim.start()

    table_nodes = Table(title="Virtual BUSMASTER Nodes Configured")
    table_nodes.add_column("Node Name", style="cyan")
    table_nodes.add_column("ECU Type", style="yellow")
    table_nodes.add_column("Cyclic Messages")
    table_nodes.add_column("Status", style="green")

    for node in sim.nodes.values():
        ids_str = ", ".join(f"0x{s.can_id:03X} ({s.period_ms}ms)" for s in node.schedules)
        table_nodes.add_row(node.name, node.ecu_type.value, ids_str, "Active" if node.enabled else "Disabled")

    console.print(table_nodes)
    console.print("\n[dim]Transmitting CAN frames onto simulated bus...[/dim]\n")

    tick_dt = 0.01  # 100 Hz tick
    sim_time = 0.0
    start_real = time.time()
    last_print = 0.0

    try:
        while sim_time < duration:
            messages = sim.tick(sim_time, tick_dt)
            sim_time += tick_dt

            if sim_time - last_print >= 1.0:
                last_print = sim_time
                elapsed = time.time() - start_real
                recent_traces = sim.get_trace_buffer(limit=3)
                sample_line = recent_traces[-1]["log_line"] if recent_traces else "..."
                bus_load = sim.calculate_bus_load()
                console.print(
                    f"  t={sim_time:.1f}s | "
                    f"Msgs={sim.total_messages} | "
                    f"Rate={sim.total_messages / max(0.1, elapsed):.0f} msg/s | "
                    f"Bus Load={bus_load:.1f}% | "
                    f"[dim]{sample_line}[/dim]"
                )

    except KeyboardInterrupt:
        console.print("\n[yellow]BUSMASTER Simulation interrupted by user.[/yellow]")

    sim.stop()
    elapsed = time.time() - start_real

    # Final summary table
    summary = Table(title="BUSMASTER Simulation Summary")
    summary.add_column("Node Name", style="cyan")
    summary.add_column("Tx Count", justify="right")
    summary.add_column("Error Count", justify="right")

    for node in sim.nodes.values():
        summary.add_row(node.name, str(node.tx_count), str(node.error_count))

    summary.add_row("TOTAL BUS FRAMES", str(sim.total_messages), "0", style="bold green")
    console.print(summary)

    if export_log:
        out_path = Path(export_log)
        sim.export_log(out_path)
        console.print(f"[green]SUCCESS: BUSMASTER trace exported to: {out_path.resolve()}[/green]")
    else:
        # Save a default log to logs/busmaster_latest.log
        default_log = Path("logs/busmaster_latest.log")
        default_log.parent.mkdir(parents=True, exist_ok=True)
        sim.export_log(default_log)
        console.print(f"[dim]Trace saved to default: {default_log.resolve()}[/dim]")


@cli.command(name="busmaster-replay")
@click.option("--file", "log_file", required=True, help="Path to BUSMASTER .log file")
@click.option("--speed", default=1.0, type=float, help="Playback speed multiplier (e.g. 1.0, 2.0)")
@click.pass_context
def busmaster_replay(ctx: click.Context, log_file: str, speed: float) -> None:
    """Replay a BUSMASTER .log file through the intrusion detection engine."""
    from can_security.can.busmaster import BusmasterPlaybackEngine
    from can_security.detection.rules import RuleEngine

    config = ctx.obj["config"]
    log_path = Path(log_file)
    if not log_path.exists():
        console.print(f"[red]Error: File not found: {log_path}[/red]")
        sys.exit(1)

    console.print(
        Panel(
            f"[bold cyan]BUSMASTER Log Replay & Security Analysis[/bold cyan]\n"
            f"File: {log_path.name} | Speed: {speed}x",
            title="[BUSMASTER Replay]",
            border_style="cyan",
        )
    )

    engine = BusmasterPlaybackEngine(log_path, real_time=True if speed <= 2.0 else False, playback_speed=speed)
    engine.start()

    rule_engine = RuleEngine(config.can_id_definitions, config.detection_rules)

    total_msgs = 0
    total_violations = 0
    start_real = time.time()

    while engine.is_active():
        msg = engine.receive(timeout=0.1)
        if msg is None:
            break
        total_msgs += 1
        evidence = rule_engine.evaluate(msg)
        if evidence:
            total_violations += 1
            for ev in evidence:
                console.print(
                    f"  [red][VIOLATION][/red] ID={msg.can_id_hex} Rule={ev.rule.value}: {ev.description}"
                )

    engine.stop()
    elapsed = time.time() - start_real
    console.print(
        f"[green]Replay complete: {total_msgs} messages analyzed in {elapsed:.2f}s. "
        f"Security violations flagged: {total_violations}[/green]"
    )


@cli.command(name="busmaster-export")
@click.option("--duration", default=5, help="Simulation duration in seconds")
@click.option("--output", default="logs/busmaster_export.log", help="Output file path")
@click.pass_context
def busmaster_export(ctx: click.Context, duration: int, output: str) -> None:
    """Run a quick simulation and export a BUSMASTER-compatible .log file."""
    from can_security.can.busmaster import BusmasterSimulator

    console.print(f"[cyan]Generating BUSMASTER trace for {duration} seconds...[/cyan]")
    sim = BusmasterSimulator()
    sim.start()

    tick_dt = 0.01
    sim_time = 0.0
    while sim_time < duration:
        sim.tick(sim_time, tick_dt)
        sim_time += tick_dt

    sim.stop()
    out_path = Path(output)
    sim.export_log(out_path)
    console.print(f"[green]SUCCESS: Exported {sim.total_messages} frames to BUSMASTER log: {out_path.resolve()}[/green]")


def main() -> None:
    """Entry point."""
    cli(obj={})


if __name__ == "__main__":
    main()
