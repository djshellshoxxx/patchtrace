<!-- Hand-written from the ghidriff 1.0.0 markdown writer (markdown.py); not output of a real run. -->
# Visual Diff

# Deleted

## Util::old_helper

### Function Meta

# Added

## new_helper

# Modified

*Modified functions contain code changes*

## small_fix

### small_fix Diff

```diff
--- small_fix
+++ small_fix
@@ -1,3 +1,3 @@
-  if (x > 1)
+  if (x > 2)
   return;
```

## Parser::parse_header

### Parser::parse_header Diff

```diff
--- Parser::parse_header
+++ Parser::parse_header
@@ -1,5 +1,8 @@
-  a();
-  b();
+  a2();
+  if (n > len) return -1;
+  b2();
+  c();
```

### Parser::parse_header Code

```c
#include <stdio.h>
## not a heading
```

# Modified (No Code Changes)

## only_moved

### only_moved Diff
