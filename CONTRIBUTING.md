# Developer Guide

Thank you for taking the time out to contribute to project Antrea!

## Contribute

### Inclusive Naming

For symbol names and documentation, do not introduce new usage of harmful
language such as 'master / slave' (or 'slave' independent of 'master') and
'blacklist / whitelist'. For more information about what constitutes harmful
language and for a reference word replacement list, please refer to the
[Inclusive Naming Initiative](https://inclusivenaming.org/).

We are committed to removing all harmful language from the project. If you
detect existing usage of harmful language in code or documentation, please
report the issue to us or open a Pull Request to address it directly. Thanks!

### Sign-off Your Work

As a CNCF project, Antrea must enforce the [Developer Certificate of
Origin](https://developercertificate.org/) (DCO) on all Pull Requests. We
require that for all commits constituting the Pull Request, the commit message
contains the `Signed-off-by` line with an email address that matches the commit
author. By adding this line to their commit messages, contributors *sign-off*
that they adhere to the requirements of the DCO.

Git provides the `-s` command-line option to append the required line
automatically to the commit message:

```bash
git commit -s -m 'This is my commit message'
```

For an existing commit, you can also use this option with `--amend`:

```bash
git commit -s --amend
```

If more than one person works on something it's possible for more than one
person to sign-off on it. For example:

```bash
Signed-off-by: Some Developer somedev@example.com
Signed-off-by: Another Developer anotherdev@example.com
```

We use the [DCO Github App](https://github.com/apps/dco) to enforce that all
commits in a Pull Request include the required `Signed-off-by` line. If this is
not the case, the app will report a failed status for the Pull Request and it
will be blocked from being merged.

Compared to our earlier CLA, DCO tends to make the experience simpler for new
contributors. If you are contributing as an employee, there is no need for your
employer to sign anything; the DCO assumes you are authorized to submit
contributions (it's your responsibility to check with your employer).
