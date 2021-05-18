# niwl-server

Server Implementation for the [niwl system](https://git.openprivacy.ca/openprivacy/niwl)

## Building

Requires `libsqlite3`
    
    sudo apt install libsqlite3-dev
    
## Running

First setup the database:

    cat sql/create.sql | sqlite3 tags.sqlite
 