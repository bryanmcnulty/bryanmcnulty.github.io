---
title: "HTB • Juggling Facts"
tags:
  - "Web"
  - "Beginner"
  - "PHP"
  - "Type Juggling"
  - "Code Review"
  - "Very Easy Difficulty"
excerpt: "Juggling Facts is a web challenge released on Hack the Box that is marked as very easy and involves finding and exploiting a PHP type juggling vulnerability in a web application"
categories:
  - "Writeups"
  - "Hack the Box Challenges"
---

Juggling Facts is a web challenge released on [**Hack the Box**](https://app.hackthebox.com/challenges/juggling-facts) by [**Xclow3n**](https://app.hackthebox.com/users/172213) that is marked as very easy and involves finding and exploiting a PHP type juggling vulnerability in a web application

> An organization seems to possess knowledge of the true nature of pumpkins. Can you find out what they honestly know and uncover this centuries-long secret once and for all?

## Code Review

In `index.php`{:.filepath}, we can see that the PHP application only has two endpoints at `/`{:.filepath} and `/api/getfacts`{:.filepath}, and they both map to `controllers/IndexController.php`{:.filepath}.

```php
<?php

class IndexController extends Controller
{
    public function __construct()
    {
        parent::__construct();
    }

    public function index($router)
    {
        $router->view('index');
    }

    public function getfacts($router)
    {
        $jsondata = json_decode(file_get_contents('php://input'), true);

        if ( empty($jsondata) || !array_key_exists('type', $jsondata))
        {
            return $router->jsonify(['message' => 'Insufficient parameters!']);
        }

        if ($jsondata['type'] === 'secrets' && $_SERVER['REMOTE_ADDR'] !== '127.0.0.1')
        {
            return $router->jsonify(['message' => 'Currently this type can be only accessed through localhost!']);
        }

        switch ($jsondata['type'])
        {
            case 'secrets':
                return $router->jsonify([
                    'facts' => $this->facts->get_facts('secrets')
                ]);

            case 'spooky':
                return $router->jsonify([
                    'facts' => $this->facts->get_facts('spooky')
                ]);
            
            case 'not_spooky':
                return $router->jsonify([
                    'facts' => $this->facts->get_facts('not_spooky')
                ]);
            
            default:
                return $router->jsonify([
                    'message' => 'Invalid type!'
                ]);
        }
    }
}
```
{:file="controllers/IndexController.php"}

The endpoint `/`{:.filepath} does not ingest any user input, so we're probably not interested in that. The `/api/getfacts`{:.filepath} endpoint looks to parse the request body as JSON on line 17, then process the _type_ key which is passed in the request body.

Things get interesting when the application seems to block requests where _type_ is set to "secrets", and the client IP address is not 127.0.0.1. Notice how the **strict comparison** operator `===` is used to compare the values on line 24.

The application then uses a **switch statement** to compare _type_ to "secrets", and returns some secret content if they match. This differs from the previous comparison because the switch statement works as a **loose comparison** (`==`), whereas the initial comparison is strict (`===`). This disparity can be viewed in the following tables.

![Strict comparison table](/assets/img/post/htb-challenges-juggling-facts/strict-table.png)
_Strict comparison table_

![Loose comparison table](/assets/img/post/htb-challenges-juggling-facts/loose-table.png)
_Loose comparison table_

Logic flaws caused by this are known as PHP **type juggling** vulnerabilities.

## Exploitation

In this case, the logic can be exploited by setting _type_ to _true_ in the request body. When the statement on line 24 compares _type_ and "secrets", it should not match, but when these are compared on line 31, they should match. Let's try this out with [curl](https://github.com/curl/curl).

```bash
addr='127.0.0.1:1337' # Change this
curl "$addr/api/getfacts" -d '{"type":true}'
```

The flag is returned!