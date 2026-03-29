#!/usr/bin/env python3
"""
ML-KEM Hybrid Benchmark Suite — Statistical Analysis & Publication Plots

Reads benchmark CSV/JSON results and produces:
  - Statistical summary tables
  - Publication-ready comparison charts (matplotlib)
  - LaTeX-formatted result tables

Usage:
    python3 benchmark-analyze.py --input ./benchmark-results/20260329_120000 --output ./analysis
"""

import argparse
import json
import os
import sys
from pathlib import Path

try:
    import pandas as pd
    import numpy as np
except ImportError:
    print("ERROR: pandas and numpy required. Install: pip install pandas numpy")
    sys.exit(1)

try:
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    import matplotlib.pyplot as plt
    import matplotlib.ticker as ticker
    HAS_MPL = True
except ImportError:
    HAS_MPL = False
    print("WARNING: matplotlib not found. Plots will be skipped.")

# ---- Style ----
COLORS = {
    'X25519':              '#6b7280',  # gray
    'ML-KEM-512':          '#3b82f6',  # blue
    'ML-KEM-768':          '#8b5cf6',  # purple
    'ML-KEM-1024':         '#ef4444',  # red
    'HQC-128':             '#f59e0b',  # amber
    'HQC-192':             '#f97316',  # orange
    'HQC-256':             '#dc2626',  # dark red
    'X25519 + ML-KEM-512': '#22d3ee',  # cyan
    'X25519 + ML-KEM-768': '#a78bfa',  # light purple
    'X25519 + ML-KEM-1024':'#f87171',  # light red
    'X25519 + HQC-128':    '#fbbf24',  # light amber
}


def load_results(input_dir: str) -> dict:
    """Load CSV and JSON benchmark results."""
    data = {}

    csv_path = os.path.join(input_dir, 'micro_results.csv')
    if os.path.exists(csv_path):
        data['csv'] = pd.read_csv(csv_path)
        print(f"Loaded CSV: {len(data['csv'])} rows")

    json_path = os.path.join(input_dir, 'micro_results.json')
    if os.path.exists(json_path):
        with open(json_path) as f:
            data['json'] = json.load(f)
        print(f"Loaded JSON results")

    return data


def statistical_summary(df: pd.DataFrame, output_dir: str):
    """Generate statistical summary tables."""
    os.makedirs(output_dir, exist_ok=True)

    kem_df = df[df['type'] == 'kem'].copy()
    hybrid_df = df[df['type'] == 'hybrid'].copy()

    # KEM summary
    if not kem_df.empty:
        summary = kem_df[[
            'algorithm', 'nist_level',
            'keygen_mean_us', 'encaps_mean_us', 'decaps_mean_us',
            'keygen_ci95_low', 'keygen_ci95_high',
            'encaps_ci95_low', 'encaps_ci95_high',
            'decaps_ci95_low', 'decaps_ci95_high',
            'wire_bytes', 'samples'
        ]].round(3)

        summary.to_csv(os.path.join(output_dir, 'kem_summary.csv'), index=False)
        print("\nKEM Benchmark Summary:")
        print(summary.to_string(index=False))

    # Hybrid summary
    if not hybrid_df.empty:
        summary = hybrid_df[[
            'algorithm', 'nist_level',
            'keygen_mean_us', 'encaps_mean_us', 'decaps_mean_us',
            'wire_bytes'
        ]].round(3)

        summary.to_csv(os.path.join(output_dir, 'hybrid_summary.csv'), index=False)
        print("\nHybrid Benchmark Summary:")
        print(summary.to_string(index=False))

    # Overhead analysis: hybrid vs classical baseline
    if not kem_df.empty and not hybrid_df.empty:
        x25519_row = kem_df[kem_df['algorithm'] == 'X25519']
        if not x25519_row.empty:
            baseline_enc = x25519_row.iloc[0]['encaps_mean_us']
            baseline_dec = x25519_row.iloc[0]['decaps_mean_us']
            baseline_wire = x25519_row.iloc[0]['wire_bytes']

            overhead = hybrid_df[['algorithm', 'nist_level']].copy()
            overhead['encaps_overhead_us'] = hybrid_df['encaps_mean_us'] - baseline_enc
            overhead['decaps_overhead_us'] = hybrid_df['decaps_mean_us'] - baseline_dec
            overhead['wire_overhead_bytes'] = hybrid_df['wire_bytes'] - baseline_wire
            overhead['encaps_overhead_pct'] = (overhead['encaps_overhead_us'] / baseline_enc * 100).round(1)

            overhead.to_csv(os.path.join(output_dir, 'overhead_analysis.csv'), index=False)
            print("\nOverhead vs X25519 Baseline:")
            print(overhead.to_string(index=False))


def plot_kem_comparison(df: pd.DataFrame, output_dir: str):
    """Bar chart comparing KEM keygen/encaps/decaps times."""
    if not HAS_MPL:
        return

    kem_df = df[df['type'] == 'kem'].sort_values('nist_level')
    if kem_df.empty:
        return

    fig, axes = plt.subplots(1, 3, figsize=(14, 5), sharey=False)
    fig.suptitle('KEM Algorithm Performance Comparison', fontsize=14, fontweight='bold')

    operations = [
        ('keygen_mean_us', 'Key Generation', 'keygen_ci95_low', 'keygen_ci95_high'),
        ('encaps_mean_us', 'Encapsulation', 'encaps_ci95_low', 'encaps_ci95_high'),
        ('decaps_mean_us', 'Decapsulation', 'decaps_ci95_low', 'decaps_ci95_high'),
    ]

    for ax, (col, title, ci_low, ci_high) in zip(axes, operations):
        algorithms = kem_df['algorithm'].values
        means = kem_df[col].values
        colors = [COLORS.get(a, '#888888') for a in algorithms]

        yerr_low = means - kem_df[ci_low].values
        yerr_high = kem_df[ci_high].values - means
        yerr = np.array([yerr_low, yerr_high])
        yerr = np.maximum(yerr, 0)  # ensure non-negative

        bars = ax.bar(range(len(algorithms)), means, color=colors,
                      yerr=yerr, capsize=4, edgecolor='black', linewidth=0.5)
        ax.set_xticks(range(len(algorithms)))
        ax.set_xticklabels(algorithms, rotation=45, ha='right', fontsize=8)
        ax.set_title(title)
        ax.set_ylabel('Time (us)')
        ax.yaxis.set_major_formatter(ticker.FormatStrFormatter('%.1f'))

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'kem_comparison.pdf'), dpi=300, bbox_inches='tight')
    plt.savefig(os.path.join(output_dir, 'kem_comparison.png'), dpi=150, bbox_inches='tight')
    plt.close()
    print("Generated: kem_comparison.pdf/png")


def plot_hybrid_overhead(df: pd.DataFrame, output_dir: str):
    """Stacked bar chart showing classical vs PQ overhead in hybrid."""
    if not HAS_MPL:
        return

    hybrid_df = df[df['type'] == 'hybrid'].sort_values('nist_level')
    kem_df = df[df['type'] == 'kem']
    if hybrid_df.empty:
        return

    fig, ax = plt.subplots(figsize=(10, 6))
    fig.suptitle('Hybrid Key Exchange: Handshake Overhead', fontsize=14, fontweight='bold')

    algorithms = hybrid_df['algorithm'].values
    total_enc = hybrid_df['encaps_mean_us'].values
    wire_bytes = hybrid_df['wire_bytes'].values

    colors = [COLORS.get(a, '#888888') for a in algorithms]
    x = range(len(algorithms))

    # Main bars: encapsulation time
    bars = ax.bar(x, total_enc, color=colors, edgecolor='black', linewidth=0.5)

    # Annotate with wire bytes
    for i, (bar, wb) in enumerate(zip(bars, wire_bytes)):
        ax.text(bar.get_x() + bar.get_width() / 2., bar.get_height() + 0.5,
                f'{wb}B', ha='center', va='bottom', fontsize=8, color='gray')

    ax.set_xticks(x)
    ax.set_xticklabels(algorithms, rotation=45, ha='right', fontsize=9)
    ax.set_ylabel('Encapsulation Time (us)')
    ax.set_xlabel('Hybrid Configuration')

    # Add X25519 baseline line
    x25519_row = kem_df[kem_df['algorithm'] == 'X25519']
    if not x25519_row.empty:
        baseline = x25519_row.iloc[0]['encaps_mean_us']
        ax.axhline(y=baseline, color='gray', linestyle='--', linewidth=1,
                    label=f'X25519 baseline ({baseline:.1f}us)')
        ax.legend(fontsize=9)

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'hybrid_overhead.pdf'), dpi=300, bbox_inches='tight')
    plt.savefig(os.path.join(output_dir, 'hybrid_overhead.png'), dpi=150, bbox_inches='tight')
    plt.close()
    print("Generated: hybrid_overhead.pdf/png")


def plot_wire_size_comparison(df: pd.DataFrame, output_dir: str):
    """Compare handshake wire sizes across algorithms."""
    if not HAS_MPL:
        return

    fig, ax = plt.subplots(figsize=(10, 5))
    fig.suptitle('TLS Handshake Wire Size (pk + ciphertext)', fontsize=14, fontweight='bold')

    all_df = df.sort_values('wire_bytes')
    algorithms = all_df['algorithm'].values
    wire = all_df['wire_bytes'].values
    colors = [COLORS.get(a, '#888888') for a in algorithms]

    bars = ax.barh(range(len(algorithms)), wire, color=colors,
                    edgecolor='black', linewidth=0.5)

    for i, (bar, w) in enumerate(zip(bars, wire)):
        ax.text(bar.get_width() + 20, bar.get_y() + bar.get_height() / 2.,
                f'{w:,}B', ha='left', va='center', fontsize=8)

    ax.set_yticks(range(len(algorithms)))
    ax.set_yticklabels(algorithms, fontsize=9)
    ax.set_xlabel('Bytes on Wire')

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'wire_size.pdf'), dpi=300, bbox_inches='tight')
    plt.savefig(os.path.join(output_dir, 'wire_size.png'), dpi=150, bbox_inches='tight')
    plt.close()
    print("Generated: wire_size.pdf/png")


def generate_latex_table(df: pd.DataFrame, output_dir: str):
    """Generate LaTeX table for paper inclusion."""
    kem_df = df[df['type'] == 'kem'].sort_values('nist_level')

    latex = r"""\begin{table}[t]
\centering
\caption{KEM Algorithm Performance Comparison (mean $\pm$ 95\% CI, microseconds)}
\label{tab:kem-benchmark}
\begin{tabular}{lccccr}
\toprule
\textbf{Algorithm} & \textbf{NIST} & \textbf{KeyGen} & \textbf{Encaps} & \textbf{Decaps} & \textbf{Wire (B)} \\
\midrule
"""
    for _, row in kem_df.iterrows():
        kg_ci = f"${row['keygen_mean_us']:.1f} \\pm {(row['keygen_ci95_high'] - row['keygen_mean_us']):.1f}$"
        enc_ci = f"${row['encaps_mean_us']:.1f} \\pm {(row['encaps_ci95_high'] - row['encaps_mean_us']):.1f}$"
        dec_ci = f"${row['decaps_mean_us']:.1f} \\pm {(row['decaps_ci95_high'] - row['decaps_mean_us']):.1f}$"

        latex += f"    {row['algorithm']} & {row['nist_level']} & {kg_ci} & {enc_ci} & {dec_ci} & {int(row['wire_bytes']):,} \\\\\n"

    latex += r"""
\bottomrule
\end{tabular}
\end{table}
"""

    with open(os.path.join(output_dir, 'kem_table.tex'), 'w') as f:
        f.write(latex)
    print("Generated: kem_table.tex")


def main():
    parser = argparse.ArgumentParser(description='ML-KEM Benchmark Analysis')
    parser.add_argument('--input', required=True, help='Input directory with benchmark results')
    parser.add_argument('--output', required=True, help='Output directory for analysis')
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    print("=" * 60)
    print("  ML-KEM Hybrid Benchmark — Analysis Pipeline")
    print("=" * 60)

    data = load_results(args.input)

    if 'csv' not in data:
        print("ERROR: No CSV results found. Run benchmarks first.")
        sys.exit(1)

    df = data['csv']

    print("\n--- Statistical Summary ---")
    statistical_summary(df, args.output)

    print("\n--- Generating Plots ---")
    plot_kem_comparison(df, args.output)
    plot_hybrid_overhead(df, args.output)
    plot_wire_size_comparison(df, args.output)

    print("\n--- Generating LaTeX ---")
    generate_latex_table(df, args.output)

    print(f"\nAnalysis complete. Output: {args.output}/")


if __name__ == '__main__':
    main()
