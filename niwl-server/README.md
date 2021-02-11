
## Building

Requires `libsqlite3`
    
    sudo apt install libsqlite3-dev
    
## Running

First setup the database:

    cat sql/create.sql | sqlite3 tags.sqlite
 