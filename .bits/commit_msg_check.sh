#! /usr/bin/env bash

SOURCE=$WORKFLOW_REPO_BRANCH
TARGET=$WORKFLOW_REPO_TARGET_BRANCH

echo "merge source" $SOURCE "target" $TARGET

common_commit_msg_starts=("bugfix: " "feature: " "revert: " "chore: ")
common_commit_msg_starts_tips="bugfix: A bug fix.\n
feature: Add a new feature.\n
revert: Revert an existing commit.\n
chore: Other changes not fall into the above types.\n"

all_ids=$(git log  origin/$TARGET..origin/$SOURCE --pretty=format:"%h")

IFS=$'\n' read -d '' -ra commit_ids <<< "$all_ids"

for id in "${commit_ids[@]}"
do

    commit_msg=$(git show --no-patch --pretty=format:"%s" $id)
    all_files=$(git show --name-only --pretty="" $id)
    IFS=$'\n' read -d '' -ra modify_files <<< "$all_files"

    echo "Start check $id commit msg: $commit_msg"

    files_nums=${#modify_files[@]}

    dismatch=1
    # Check if starts with common_commit_msg_starts_tips
    for prefix in "${common_commit_msg_starts[@]}"; do
        if [[ $commit_msg == $prefix* ]]; then
            dismatch=0
            break
        fi
    done

    # If not , then check if starts with module/filename: , such as: avformat/hls: 
    if [ $dismatch -eq 1 ]; then
        # Only change one file, should use "module/filename: " as commit msg. 
        if [ "$files_nums" -eq 1 ]; then
            parent_dir=$(dirname "$modify_files")
            file_name=$(basename "$modify_files")
            file_name_without_extension="${file_name%.*}"
            need_commit_msg_startwith=("$parent_dir/$file_name_without_extension: ")
            if [ "$parent_dir" == "." ]; then
                need_commit_msg_startwith=("$file_name_without_extension: ")
            fi

            if [[ $parent_dir == lib* ]]; then
                substring=${parent_dir#lib}
                need_commit_msg_startwith=("$substring/$file_name_without_extension: ")
            fi
            
            if [[ $commit_msg == $need_commit_msg_startwith* ]]; then
                echo "Commit msg should start with : $need_commit_msg_startwith" 
                dismatch=0
            else
                dismatch=1
            fi
        
        else
            # Multi files changed, can also use 'module/filename: ' as commit msg.
            if [[ $commit_msg =~ .*/.*:[[:space:]] ]]; then
                dismatch=0
            fi
        fi
    fi

    if [ $dismatch -eq 1 ]; then
        echo -e $id " commit msg should start with xxx/xxx:  or \n" $common_commit_msg_starts_tips ""
        exit 1
    else
        echo $id " commit msg be checked passed."
    fi

done

exit 0
