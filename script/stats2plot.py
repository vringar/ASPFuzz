import json
import re
import os
import seaborn as sns
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator
import numpy as np
from pathlib import Path
import argparse


stats = {
    "runtime": [],
    "sec": [],
    "corpus": [],
    "objectives": [],
    "executions": [],
    "exec/sec": [],
    "edges": [],
}


class LibAflLogParser:
    """Parser for libafl log files
    Extracts values and maps them to timeline with regular time interval
    """

    runtime_re = re.compile("run time: ([0-9]{1,10})h-([0-9]{1,2})m-([0-9]{1,2})s")
    client_re = re.compile("clients: ([0-9]{1,10})")
    corpus_re = re.compile("corpus: ([0-9]{1,10})")
    objectives_re = re.compile("objectives: ([0-9]{1,10})")
    executions_re = re.compile("executions: ([0-9]{1,20})")
    execsec_re = re.compile("exec/sec: ([0-9]{1,10}.[0-9]{1,10}k?)")
    edges_re = re.compile("edges: ([0-9]{1,5})")

    def __init__(self):
        self.next_timestep = 10
        self.last_timestep = 0
        self.last_max_edges = 0

        self.entries = {}
        """ Mapping from Timestamp in seconds to a dictionary of stats """

    def handle_line(self, line):
        # We always try to extract the # of edges in (CLIENT) lines
        # Global only has % which is useless for comparision across runs
        if "CLIENT" in line:
            stats_edges_re_res = re.search(self.edges_re, line)
            if stats_edges_re_res:
                new_edges = int(stats_edges_re_res[1])
                if new_edges > self.last_max_edges:
                    self.last_max_edges = new_edges
        if not "(GLOBAL)" in line:
            return
        stats_runtime_re_res = re.search(self.runtime_re, line)
        if stats_runtime_re_res is None:
            raise ValueError(f"Could not find runtime in global line: {line}")
        total_sec = (
            int(stats_runtime_re_res[3])
            + 60 * int(stats_runtime_re_res[2])
            + 3600 * int(stats_runtime_re_res[1])
        )
        self.total_sec = total_sec
        if total_sec >= self.next_timestep:
            # We "snap" the values from total_sec back to the "next_timestep"
            # This makes our values evenly spaced even if they are not in the log
            # stats_client_re_res = re.search(self.client_re, line)
            stats_corpus_re_res = re.search(self.corpus_re, line)
            stats_objectives_re_res = re.search(self.objectives_re, line)
            stats_executions_re_res = re.search(self.executions_re, line)
            stats_execsec_re_res = re.search(self.execsec_re, line)
            # stats_edges_re_res = re.search(self.edges_re, line)

            execs_per_sec_raw = stats_execsec_re_res[1]
            if execs_per_sec_raw[-1] == "k":
                execs_per_sec = float(execs_per_sec_raw[:-1]) * 1000
            else:
                execs_per_sec = float(execs_per_sec_raw)

            self.entries[self.next_timestep] = {
                "actual_value": total_sec,
                "corpus": int(stats_corpus_re_res[1]),
                "objectives": int(stats_objectives_re_res[1]),
                "executions": int(stats_executions_re_res[1]),
                "exec/sec": execs_per_sec,
                "edges": int(self.last_max_edges),
            }
            # Left here for historical reasons
            # Used by stats2plot
            stats["runtime"].append(
                f"{stats_runtime_re_res[1]}h-{stats_runtime_re_res[2]}m-{stats_runtime_re_res[3]}s"
            )
            stats["sec"].append(self.next_timestep)
            stats["corpus"].append(int(stats_corpus_re_res[1]))
            stats["objectives"].append(int(stats_objectives_re_res[1]))
            stats["executions"].append(int(stats_executions_re_res[1]))
            stats["exec/sec"].append(execs_per_sec)
            stats["edges"].append(self.last_max_edges)

            self.last_timestep = total_sec
            if self.next_timestep < 3600:
                self.next_timestep = self.total_sec // 10 * 10 + 10
            else:
                self.next_timestep = self.total_sec // 600 * 600 + 600


def stats2plot(stats: dict, plot_file: Path):
    t = [s / 60 for s in stats["sec"]]
    data3 = stats["edges"]
    data2 = stats["objectives"]
    data1 = stats["executions"]
    linewidth = 3
    fontsize = 26

    fig, ax1 = plt.subplots()
    fig.subplots_adjust(right=0.75)
    fig.set_figwidth(20)
    fig.set_figheight(8)

    color = sns.color_palette(palette=None)[0]
    ax1.set_xlabel("time in minutes", fontsize=fontsize)
    ax1.yaxis.set_major_locator(MaxNLocator(integer=True))
    ax1.set_ylabel("executions", color=color, fontsize=fontsize)
    ax1.plot(t, data1, color=color, linewidth=linewidth)
    ax1.tick_params(axis="y", labelcolor=color, labelsize=fontsize - 2)
    ax1.set_ylim(0.0)
    ax1.tick_params(axis="x", labelsize=fontsize - 2)
    ax1.xaxis.set_major_locator(plt.MultipleLocator(max(t) / 12))

    ax2 = ax1.twinx()
    color = sns.color_palette(palette=None)[1]
    ax2.set_ylabel("objectives", color=color, fontsize=fontsize)
    ax2.plot(t, data2, color=color, linewidth=linewidth)
    ax2.set_ylim(0.0, max(data2) + 1.0 if max(data2) >= 1.0 else 1.0)
    ax2.tick_params(axis="y", labelcolor=color, labelsize=fontsize - 2)

    ax3 = ax1.twinx()
    ax3.spines["right"].set_position(("axes", 1.1))
    color = sns.color_palette(palette=None)[2]
    ax3.set_ylabel("edges", color=color, fontsize=fontsize)
    ax3.plot(t, data3, color=color, linewidth=linewidth)
    ax3.set_ylim(0.0)
    ax3.tick_params(axis="y", labelcolor=color, labelsize=fontsize - 2)

    # otherwise the right y-label is slightly clipped
    fig.tight_layout()

    print(f"Plot written to {plot_file}")
    plt.savefig(plot_file, bbox_inches="tight")


# stats2plot(stats)

if __name__ == "__main__":
    sns.set_theme(style="white", font_scale=1.7)

    parser = argparse.ArgumentParser(description="Plot libafl log file")
    parser.add_argument(
        "log_file",
        type=str,
        help="Path to the log file",
    )
    parser.add_argument(
        "-p",
        "--plot_file",
        type=str,
        required=False,
        help="File name to write the plot to",
    )
    parser.add_argument(
        "-j",
        "--json_file",
        type=str,
        required=False,
        help="File name to write the plot to",
    )
    args = parser.parse_args()

    log_file = Path(args.log_file)
    if not os.path.isfile(log_file):
        print(f"{log_file} is not a valid file")
        exit(1)
    analyzer = LibAflLogParser()
    with open(log_file, "r") as f:
        for line in f:
            analyzer.handle_line(line)
    if args.json_file:
        json_file = Path(args.json_file)
        json_file = (
            json_file if json_file.suffix == ".json" else json_file.with_suffix(".json")
        )
        with open(log_file.parent / json_file, "w") as f:
            json.dump(analyzer.entries, f, indent=0)
    if args.plot_file:
        plot_file = Path(args.plot_file)
        plot_file = (
            plot_file if plot_file.suffix == ".png" else plot_file.with_suffix(".png")
        )
        stats2plot(stats, log_file.parent / plot_file)
    print("Analyzer total sec", analyzer.total_sec)
