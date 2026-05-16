#!/bin/bash
set -e

# Target directory (defaults to current directory)
TARGET_DIR="${1:-.}"

# Configuration
SKIP_DIRS=(".git" ".github" "conf")
SKIP_FILES=("index.html" ".DS_Store" ".gitignore")

# Function to generate index for a single directory
generate_index() {
    local dir="$1"

    # Skip root directory to allow Jekyll to render README.md
    if [ "$dir" == "$TARGET_DIR" ] || [ "$dir" == "$TARGET_DIR/" ]; then
        return
    fi
    local index_file="$dir/index.html"

    # Calculate relative path for title
    local rel_path="${dir#$TARGET_DIR}"
    [ -z "$rel_path" ] && rel_path="/"

    # Calculate path to root for assets
    local path_to_root=""
    if [ "$dir" != "$TARGET_DIR" ] && [ "$dir" != "$TARGET_DIR/" ]; then
        local clean_dir="${dir#$TARGET_DIR/}"
        clean_dir="${clean_dir%/}"

        # Count slashes to determine depth
        local depth
        depth=$(echo "$clean_dir" | tr -cd '/' | wc -c)

        # Add ../ for each level
        for ((i=0; i<=depth; i++)); do
            path_to_root="../$path_to_root"
        done
    fi

    echo "Generating index for $rel_path..."

    # Start HTML
    cat <<EOF > "$index_file"
<html>
<head>
    <title>Index of $rel_path</title>
    <link rel="stylesheet" href="${path_to_root}assets/css/style.css">
</head>
<body>
<h1>Index of $rel_path</h1>
<hr><pre><a href="../">../</a>
EOF

    # List items
    # We use a subshell to change directory to listing target so globs work simply
    (
        cd "$dir" || exit 1

        # Directories
        for d in */; do
            [ -e "$d" ] || continue
            dirname="${d%/}"

            # Check skip list
            skip=false
            for s in "${SKIP_DIRS[@]}"; do
                if [ "$dirname" == "$s" ]; then skip=true; break; fi
            done
            if [ "$skip" == "true" ]; then continue; fi

            echo "<a href=\"$d\">$d</a>" >> "index.html"
        done

        # Files
        for f in *; do
            [ -e "$f" ] || continue
            [ -d "$f" ] && continue

            # Check skip list
            skip=false
            for s in "${SKIP_FILES[@]}"; do
                if [ "$f" == "$s" ]; then skip=true; break; fi
            done
            if [ "$skip" == "true" ]; then continue; fi

            echo "<a href=\"$f\">$f</a>" >> "index.html"
        done
    )

    # End HTML
    cat <<EOF >> "$index_file"
</pre><hr>
</body>
</html>
EOF
}

# Recursively find all directories and generate indices
# We use find to get all directories, excluding .git, .github, and conf
find "$TARGET_DIR" -type d -not -path '*/.*' -not -name 'conf' | sort | while read -r d; do
    generate_index "$d"
done
