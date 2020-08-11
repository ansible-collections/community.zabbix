# Publishing New Versions

  1. Ensure all relevant PRs have provided changelog fragments, then generate a changelog entries for new version:
    ```
    antsibull-changelog release --version X.Y.Z --date YYYY-MM-DD
    ```
  2. Update `galaxy.yml` file and `requirements.yml` example in `README.md` with the new `version` for the collection.
  3. Tag the version in Git and push to GitHub:
    ```
    git tag -a X.Y.Z
    git push origin X.Y.Z
    ```

Additional manual steps are required when automatic publish to Ansible Galaxy is not enabled in the repository. This
requires a user who has access to the `community.zabbix` namespace on Ansible Galaxy to publish the build artifact.

  4. Run the following commands to build and release the new version on Galaxy:

     ```
     ansible-galaxy collection build
     ansible-galaxy collection publish ./community-zabbix-$VERSION_HERE.tar.gz
     ```

After the version is published, verify it exists on the [Zabbix Collection Galaxy page](https://galaxy.ansible.com/community/zabbix).
