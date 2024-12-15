from collections import defaultdict
import json
import seaborn as sns
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator
from pathlib import Path
import argparse
from statistics import mean as avg


def stats2plot(stats: dict, plot_file: Path):
    n = stats["clients"]
    data1 = stats["exec/sec"]
    data2 = stats["objectives"]
    data3 = stats["edges"]
    linewidth = 3

    fontsize = 26

    fig, ax1 = plt.subplots()
    fig.subplots_adjust(right=0.75)
    fig.set_figwidth(20)
    fig.set_figheight(8)

    color = sns.color_palette(palette=None)[0]
    ax1.set_xlabel("Number of concurrent clients", fontsize=fontsize)
    ax1.yaxis.set_major_locator(MaxNLocator(integer=True))
    ax1.set_ylabel("exec/sec", color=color, fontsize=fontsize)
    ax1.plot(n, data1, color=color, linewidth=linewidth)
    ax1.tick_params(axis="y", labelcolor=color, labelsize=fontsize - 2)
    ax1.xaxis.set_ticks(n)
    ax1.tick_params(axis="x", labelsize=fontsize - 2)

    ax2 = ax1.twinx()
    color = sns.color_palette(palette=None)[1]
    ax2.set_ylabel("objectives", color=color, fontsize=fontsize)
    ax2.plot(n, data2, color=color, linewidth=linewidth)
    ax2.set_ylim(0.0, max(data2) + 1.0 if max(data2) >= 1.0 else 1.0)
    ax2.tick_params(axis="y", labelcolor=color, labelsize=fontsize - 2)

    ax3 = ax1.twinx()
    ax3.spines["right"].set_position(("axes", 1.1))
    color = sns.color_palette(palette=None)[2]
    ax3.set_ylabel("edges", color=color, fontsize=fontsize)
    ax3.set_ylim(0.0, 200.0)
    ax3.plot(n, data3, color=color, linewidth=linewidth)
    ax3.tick_params(axis="y", labelcolor=color, labelsize=fontsize - 2)

    # otherwise the right y-label is slightly clipped
    fig.tight_layout()

    print(f"Plot written to {plot_file}")
    plt.savefig(plot_file, bbox_inches="tight")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Plot results from multiple runs of LibAFL"
    )
    parser.add_argument(
        "files",
        nargs="+",
    )
    parser.add_argument(
        "-p",
        "--plot_file",
        type=str,
        help="Path to the plot file",
        required=True,
    )
    args = parser.parse_args()
    data = defaultdict(list)
    for file in args.files:
        path = Path(file)
        try:
            core_count = int(path.name.removesuffix(".json").removeprefix("stats"))
        except ValueError:
            continue
        with path.open("r") as f:
            full_sample = json.load(f)
        last_key = list(full_sample)[-1]
        print(path, last_key)
        data[core_count].append(full_sample[last_key])
    plot_file = Path(args.plot_file)
    plot_file = (
        plot_file if plot_file.suffix == ".png" else plot_file.with_suffix(".png")
    )

    def compute_avg_for_key(per_core_count_data, key):
        return avg([sample[key] for sample in per_core_count_data])

    stats = {
        "clients": [k + 1 for k in data.keys()],
        "edges": [
            compute_avg_for_key(data[core_count], "edges") for core_count in data.keys()
        ],
        "objectives": [
            compute_avg_for_key(data[core_count], "objectives")
            for core_count in data.keys()
        ],
        "exec/sec": [
            compute_avg_for_key(data[core_count], "exec/sec")
            for core_count in data.keys()
        ],
    }
    stats2plot(stats, plot_file)
