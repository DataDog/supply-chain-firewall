# Package minimum age verifier

The minimum package age verifier checks whether a given package has a certain minimum age, defined to be the number of hours elapsed since the time of the package's creation on the ecosystem's package registry.  If a given package does not have the required minimum age, a single `WARNING`-level finding is returned.

```bash
scfw run pip install foo
Package foo-1.0.1:
  - Package foo was created less than 24 hours ago: treat new packages with caution
```

This verifier provides an additional level of protection to SCFW users against supply-chain attacks: all things being equal, recently-created packages are generally unvetted and should be treated with a greater deal of initial skepticism before being installed.

Users may configure the behavior of this verifier via the following environment variables:

* `SCFW_PACKAGE_MINIMUM_AGE`:
    Takes a positive integer number representing the desired minimum package age in hours.  A default value of 24 hours is used if this is not set.
