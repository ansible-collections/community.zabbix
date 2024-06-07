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

2. All community.* collections are usually published by Zuul, which works by you having to push a tag, and Zuul will build the collection from that tag (with the version in galaxy.yml set to the tag's version) and publish it. It's usually a good idea to take a look at [Zuul](https://ansible.softwarefactory-project.io/zuul/status) when pushing a tag and watch the release process to see whether it succeeds or not (and afterwards check on [Galaxy](https://galaxy.ansible.com/community/zabbix) whether the newest version shows up - note that it can make a few seconds after publishing finished until it actually shows up; that's new with the new Galaxy).

   If there is an error in building and it seems to be on Zuul side, the best thing is to re-push the tag to trigger the publish step another time. For that, assuming the remote for github.com/ansible-collections/community.zabbix is called upstream, you can do


    ```
    git push upstream :2.3.0 # to delete the tag
    git push --tags upstream # to re-push all tags
    ```
   That should delete and re-create the tag, and thus trigger Zuul again to publish the collection.

3. If still having problems in step 2. then create a post in "Get Help" section of [Ansible forum](https://forum.ansible.com/c/help/6/none) so somebody from admins can take a look and see/fix why new version has not been published to Galaxy (e.g. https://forum.ansible.com/t/access-to-collection/2295/4).

4. Create new Release pointing to new X.Y.Z tag https://github.com/ansible-collections/community.zabbix/releases


