# VSpace Specification

This is to document the VSpace specification in dafny.

## Current limitations

Some things the current spec should handle but doesn't. e.g., things the
implementation does at the moment. Either we change the implementation or adjust
the spec to capture these cases.

### Frame will be "arbitrary" sized, e.g., 4K, 2M or 1G on x86.

Arbitrary sized frames mean that we have to do a range query in order to find
any overlapping frames in the vspace begin, end region that we're trying to map
the frame into. *So, right now frames are limited to 4K only*

Generally this will fail:

```log
+------------------------------------------------------------+
|                      |      Mapped       |                 |
+------------------------------------------------------------+
            ^             ^
            |             |MapFrame doesn't work
            +-------------+
            |             |
            +-------------+
```

And this will work:

```log
+------------------------------------------------------------+
|                      |      Mapped       |                 |
+------------------------------------------------------------+
        ^             ^
        |             |MapFrame works
        +-------------+
        |             |
        +-------------+
```

## Promoting a mapping to a bigger mapping

This is a bit of a strange case that we allow in the model/spec where we can
extend (make bigger) an existing mapping in case there are no conflicts with
other mappings:

```log
        VA=0x1000
        +
        |
+----------------------------------------+
|       |B=0x8000 l=0x1000  |            |
+----------------------------------------+
        ^
        | MapFrame works
        |
        +-----------------------+
        |B=0x8000 l=0x2000      |
        +-----------------------+
```

```log
        VA=0x1000
        +
        |
+----------------------------------------------------------+
|       |PA=0x8000 l=0x1000 |PA=0x3000 l=0x1000 |          |
+----------------------------------------------------------+
        ^
        | MapFrame fails
        |
        +-----------------------+
        |B=0x8000 l=0x2000      |
        +-----------------------+
```

Complicates the spec as we have to find all overlapping mappings in the region
and then if there was only one overlap, and it's at the start of the current
frame and physical address matches too, we can make the mapped region bigger,
otherwise we return an error.
