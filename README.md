This repository contains the fixed `rdbgp2.rb` file, originally shipped with `KomodoIDE`.

In order to use this file, you should install `byebug`  version <= `8.2.5`:

`gem install byebug -v 8.2.5`

Of course, you can use `bundler` to manage this specific dependency.

When you want to debug you can use it as described in `VDebug` help:

```bash
export RUBYDB_LIB=/<path-to-the-folder-of-edbgp2>

# This line is optional
export RUBYDB_OPTS="PORT=9000 verbose=4 logfile=./t.log"

$RUBYDB_LIB/rdbgp2.rb <path-to-file-to-debug>
```



