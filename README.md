This repository contains a fixed version of `rdbgp2.rb` file, originally shipped with `KomodoIDE`.

This script depends on `byebug` version <= `8.2.5`:

`gem install byebug -v 8.2.5`

Of course, you can use `bundler` to manage this specific dependency.

If you use ruby version manager, point to the correct binary in the `shebang` at the top of the script.

You can use it as described in `VDebug` help:

```bash
export RUBYDB_LIB=/<path-to-the-**folder**-of-rdbgp2.rb>

# This line is optional
export RUBYDB_OPTS="PORT=9000 verbose=4 logfile=./t.log"

$RUBYDB_LIB/rdbgp2.rb <path-to-file-to-debug>
```



