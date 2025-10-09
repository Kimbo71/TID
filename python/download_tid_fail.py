"""Utility script that prints instructions for locating and downloading tid_fail.c updates."""

from textwrap import dedent


def main() -> None:
    instructions = dedent(
        """
        Downloading tid_fail.c
        ======================

        Option 1: Clone the entire repository
        -------------------------------------
        If you need to build or inspect multiple files, clone the project:

            git clone <repo-url>
            cd TID
            git checkout work
            git pull --ff-only
            ls tid_fail.c

        Replace <repo-url> with the HTTPS URL of this repository (for example a GitHub URL).
        The current fixes live on the `work` branch at commit 223c695 ("Refactor NTPL command
        helper layering"). Display that commit with:

            git show 223c695

        Option 2: Fetch only tid_fail.c with curl
        -----------------------------------------
        When you only want the single source file, download the raw file directly:

            curl -L -o tid_fail.c <raw-file-url>

        Use the Raw button in your browser to copy <raw-file-url>; on GitHub it ends with
        `/raw/<branch>/tid_fail.c`.

        Option 3: Fetch only tid_fail.c with wget
        -----------------------------------------
        wget provides an equivalent command:

            wget -O tid_fail.c <raw-file-url>

        Option 4: Download a ZIP snapshot
        ---------------------------------
        Most hosts (including GitHub) expose a ZIP archive of the repository:

            curl -L -o TID-main.zip https://github.com/<owner>/<repo>/archive/refs/heads/main.zip
            unzip TID-main.zip

        After unzipping, tid_fail.c will be inside the extracted directory. Check out the `work`
        branch afterward if you need the latest fixes.
        """
    ).strip()
    print(instructions)


if __name__ == "__main__":
    main()
