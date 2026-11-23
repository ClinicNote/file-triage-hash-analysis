
from pathlib import Path
from datetime import datetime
import hashlib
import csv

project_folder = Path(__file__).resolve().parent
reference_file = project_folder / "hashes_reference.csv"
report_file = project_folder / "triage_report.txt"


# Calculate the SHA-256 hash of a file
def calculate_sha256(file_path):
    with open(file_path, "rb") as file:
        contents = file.read()

    return hashlib.sha256(contents).hexdigest()


# Load known hashes from the CSV file
def load_known_hashes():
    known_hashes = {}

    with open(reference_file, "r", newline="") as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames:
            raise ValueError("The reference CSV is empty.")

        if "sha256" not in reader.fieldnames or "label" not in reader.fieldnames:
            raise ValueError("The reference CSV has missing columns.")

        for row in reader:
            file_hash = (row["sha256"] or "").strip().lower()
            label = (row["label"] or "").strip()

            # Skip invalid hash entries
            if len(file_hash) != 64:
                print("Skipping invalid reference hash.")
                continue

            if not all(character in "0123456789abcdef" for character in file_hash):
                print("Skipping invalid reference hash.")
                continue

            known_hashes[file_hash] = label

    return known_hashes


# Save investigation results to a text file
def save_report(results):
    with open(report_file, "w", encoding="utf-8") as file:
        for line in results:
            file.write(line + "\n")


# Ask the user which folder to scan
folder_name = input("Enter folder path (press Enter for samples): ").strip()

if folder_name == "":
    samples_folder = project_folder / "samples"
else:
    samples_folder = Path(folder_name)

    # Allow folder names inside the project folder
    if not samples_folder.is_absolute():
        samples_folder = project_folder / samples_folder


results = []
hashes = {}

print("FILE TRIAGE RESULTS")
print("-------------------")

results.append("FILE TRIAGE REPORT")
results.append("-------------------")

try:
    known_hashes = load_known_hashes()

    if samples_folder.is_dir():

        for file in sorted(samples_folder.iterdir()):

            if file.is_file():

                try:
                    name = file.name
                    size = file.stat().st_size
                    extension = file.suffix
                    file_hash = calculate_sha256(file)

                    modified = file.stat().st_mtime
                    modified_date = datetime.fromtimestamp(modified)

                    if file_hash in known_hashes:
                        status = "Known"
                        label = known_hashes[file_hash]
                    else:
                        status = "Unknown"
                        label = "Not in reference list"

                    # Display the results
                    print("Filename:", name)
                    print("Extension:", extension)
                    print("Size:", size, "bytes")
                    print("Last modified:", modified_date)
                    print("SHA-256:", file_hash)
                    print("Status:", status)
                    print("Reference label:", label)
                    print("-------------------")

                    # Add results to the report
                    results.append("Filename: " + name)
                    results.append("Extension: " + extension)
                    results.append("Size: " + str(size) + " bytes")
                    results.append("Last modified: " + str(modified_date))
                    results.append("SHA-256: " + file_hash)
                    results.append("Status: " + status)
                    results.append("Reference label: " + label)
                    results.append("-------------------")

                    # Group filenames by their hashes
                    if file_hash in hashes:
                        hashes[file_hash].append(name)
                    else:
                        hashes[file_hash] = [name]

                except OSError as error:
                    message = "Could not read file: " + file.name
                    print(message)
                    print(error)
                    results.append(message)

        # Check for duplicate files
        print("DUPLICATE FILE CHECK")
        results.append("DUPLICATE FILE CHECK")

        duplicates_found = False

        for file_hash in hashes:
            if len(hashes[file_hash]) > 1:
                message = "Duplicate files: " + ", ".join(hashes[file_hash])
                print(message)
                results.append(message)
                results.append("Matching SHA-256: " + file_hash)
                duplicates_found = True

        if duplicates_found == False:
            print("No duplicates found.")
            results.append("No duplicates found.")

        # Explain the security meaning
        results.append("-------------------")
        results.append("SECURITY INTERPRETATION")
        results.append("A matching SHA-256 hash suggests identical file content.")
        results.append("An unknown hash does not mean a file is malicious.")
        results.append("A known hash does not prove a file is safe.")

        save_report(results)
        print("\nReport saved as triage_report.txt")

    else:
        print("Folder not found:", samples_folder)

except (OSError, ValueError, KeyError, csv.Error) as error:
    print("Error loading the reference file:", error)



