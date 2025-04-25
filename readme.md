# Secure Coding

## Tiny Secondhand Shopping Platform

## Requirements

If you don't have a miniconda(or anaconda), you can install it on this url. - https://docs.anaconda.com/free/miniconda/index.html

```
git clone https://ycseo-git/whs-secure-coding
conda env create -f enviroments.yaml
```

## Usage

Run the server process.

```
conda activate
python app.py
```

If you want to test on external machine, you can utilize the ngrok to forwarding the url.
```
# optional
sudo snap install ngrok
ngrok http 5000
```

## Please note that
There are no functions to give users admin privileges or charge credit.
So, if you want to test the pages or functions that are only for admins, you must give privileges to the accounts manually using SQL queries.

```
UPDATE user
SET is_admin = 1
WHERE username = 'admin';
```

Additionally, the recharge feature is not implemented, so you need to manually adjust the balance via SQL queries.

```
UPDATE user
SET balance = balance + 500
WHERE username = 'you';
```

This approach is more secure than exposing such functions directly on the web page.
~~In fact, I did this because there isn't enough time to implement it. Apologies for not cleaning up the comments properly. But please bear with me.~~
