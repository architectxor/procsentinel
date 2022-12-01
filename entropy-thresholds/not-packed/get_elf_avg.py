from pathlib import Path
import bintropy

elfs_path = Path(".")
avg_entropies = []
highest_block_entropies = []
broken_elfs = []
for elf in elfs_path.iterdir():
    try:
        highest, avg = bintropy.bintropy(elf, decide=False)
        avg_entropies.append(avg)
        highest_block_entropies.append(highest)
    except OSError as e:
        broken_elfs.append(elf)
      

averagest = sum(avg_entropies) / len(avg_entropies)
avg_highest = sum(highest_block_entropies) / len(highest_block_entropies)

print(f"There are {len(broken_elfs) - 1} broken ELF executables.")
print(f"AVG: {averagest}\t\tHIGH: {avg_highest}")
