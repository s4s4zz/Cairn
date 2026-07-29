# Closed-platform synthetic fixture sources

These files are project-authored, vendor-neutral inputs for the CP0 capability
matrix. They contain no commercial classes, binaries, decompiled output, product
names, keys, or installation media.

Tests that need JAR, WAR, EAR, or standalone class inputs must compile and package
these sources inside a temporary directory. Generated binaries must not be added
to the repository. `fixture-matrix-v1.json` defines the required archive topology
and the feature each generated artifact is expected to exercise.
