# Publishing New Versions

## Steps to take on forked repository

1. Create new branch X.Y.Zprep.
2. Check all merged PRs since last release and verify they had changelog fragments included. If not add them to _changelogs/fragments/missing.yml_ and commit.
3. Generate a changelog entries for new version:


    ```
    # python3 -m venv antsibull-env && source antsibull-env/bin/activate && pip3 install antsibull-changelog
    antsibull-changelog release --version X.Y.Z --date YYYY-MM-DD
    ```

4. Update `galaxy.yml` file and `requirements.yml` example in `README.md` with the new `version` for the collection and commit.
5. Push new branch for the review `git push origin X.Y.Zprep`.
6. Before merging, ensure that date used for `antsibull-changelog` command is consistent with the day that PR was merged on.

## Steps to take on ansible-collections/community.zabbix

1. After merging the branch from previous steps, tag the version via git and push to GitHub:


    ```
    git tag -a X.Y.Z
    git push origin X.Y.Z
    ```

2. Create new Release pointing to new X.Y.Z tag https://github.com/ansible-collections/community.zabbix/releases

Additional manual steps are required when automatic publish to Ansible Galaxy is not enabled in the repository. This
requires a user who has access to the `community.zabbix` namespace on Ansible Galaxy to publish the build artifact.

3. Run the following commands to build and release the new version on Galaxy:

   ```
   ansible-galaxy collection build
   ansible-galaxy collection publish ./community-zabbix-$VERSION_HERE.tar.gz
   ```

After the version is published, verify it exists on the [Zabbix Collection Galaxy page](https://galaxy.ansible.com/community/zabbix).
