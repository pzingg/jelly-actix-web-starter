-- Creates an identities table, along with some associated helpers.

create or replace function update_timestamp() returns trigger as $$
begin
    new.updated = now();
    return new;
end;
$$ language 'plpgsql';

create table if not exists identities (
    id serial primary key,
    account_id int not null,
    provider text not null,
    username text not null,
    name text,
    refresh_token text,
    created timestamp with time zone not null default now(),
    updated timestamp with time zone not null default now(),
    foreign key(account_id) references accounts(id)
);

create index identities_provider_idx on identities (provider);
create unique index identities_unique_provider_username_idx on identities (provider, lower(username));

create trigger identity_updated before insert or update on identities
for each row execute procedure update_timestamp();
