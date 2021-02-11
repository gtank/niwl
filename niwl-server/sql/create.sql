create table if not exists tags (
              id text primary key,
              tag blob not null unique
          )