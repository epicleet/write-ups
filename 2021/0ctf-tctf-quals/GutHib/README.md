Challenge
===

What happens on GutHib, stays on GutHib.

repo: [awesome-ctf/TCTF2021-Guthib](https://github.com/awesome-ctf/TCTF2021-Guthib)



Solution
===

The challenge shows a repository where the author seemingly checked in a secret and later removed it using [bfg](https://rtyley.github.io/bfg-repo-cleaner/) + force push.

As shown in [this StackOverflow answer](https://stackoverflow.com/questions/872565/remove-sensitive-files-and-their-commits-from-git-history/32840254#32840254), force-pushing is not enough to remove the secret from GitHub. By accessing `https://github.com/:org/:repo/commit/{sha}`, one can still visualize the commit. Moreover, the commit ids are still visible in GitHub APIs.

According to https://docs.github.com/en/rest/reference/activity, one can list all event from a repository by querying the `https://api.github.com/repos/:org/:repo/events`. The results are paginated and the `page` parameter defines which page to fetch.

After fetching the first 4 pages of the events, we see a `CreatedEvent`, this seems to be the last page.

```json
[
  {
    "id": "17020911707",
    "type": "CreateEvent",
    "actor": {
      "id": 7986667,
      "login": "HenryzhaoH",
      "display_login": "HenryzhaoH",
      "gravatar_id": "",
      "url": "https://api.github.com/users/HenryzhaoH",
      "avatar_url": "https://avatars.githubusercontent.com/u/7986667?"
    },
    "repo": {
      "id": 382436656,
      "name": "awesome-ctf/TCTF2021-Guthib",
      "url": "https://api.github.com/repos/awesome-ctf/TCTF2021-Guthib"
    },
    "payload": {
      "ref": null,
      "ref_type": "repository",
      "master_branch": "master",
      "description": null,
      "pusher_type": "user"
    },
    "public": false,
    "created_at": "2021-07-02T18:53:28Z",
    "org": {
      "id": 86848883,
      "login": "awesome-ctf",
      "gravatar_id": "",
      "url": "https://api.github.com/orgs/awesome-ctf",
      "avatar_url": "https://avatars.githubusercontent.com/u/86848883?"
    }
  }
]
```

We now proceed to find all possible commit ids present in the events

```
$ grep -ho '[a-f0-9]\{40\}' repoevents*.json | sort | uniq
2ab09dd2f56b64a47447dbe49caeb48710c9fcfe
355bcf4ef7cb32e18064ffc76b484b2faf651c4e
4bc62aa59208d02219e6e8b83622afcf14c752ac
4d9ccc752eb581578209377dc722ebf2b88fdc73
5d6f35f6f901cd2c94bd8fd50aff64f8c179bff5
6442a84e359a19c4aeb1ef792a04bb9206140926
6ae87cd1d9b35cfdca4f56f8d8ac78508a404a8b
71b64665ec865ce8c15c11f44e76b6b1c4d56bdf
78d0c3836d286188b15a774cc58c8dc79e117f51
8cd3af6b9cee40cb070b317e6e9cd398ab95632c
932795a9ea18ee35ae0f5339973ef0d2d9dd9bca
a17ed270522072895e5e2b11b6fdd0e9a210fdfb
b0fa86265392dbbbc5c0d8c5a1344bf8a592c4aa
beb0adbb133a503e280b341c3ca69bf2ae9db061
bee074d40dbd6d4d82844fa9c28fb69a0abed1c9
d7377a55f88ce0a97e993817d16c61d6f96a5085
da883505ed6754f328296cac1ddb203593473967
e620525f9f5576859318e1ea836ca0a60a357d95
e7342f33268d4443c91c3a86e92ae171a75aeed0
```

Trying each of the found commits in `https://github.com/awesome-ctf/TCTF2021-Guthib/commit/{sha}`, we end up finding the flag being removed in https://github.com/awesome-ctf/TCTF2021-Guthib/commit/6442a84e359a19c4aeb1ef792a04bb9206140926

![](https://i.imgur.com/NhuwBJ1.png)

`flag{ZJaNicLjnDytwqosX8ebwiMdLGcMBL}`

Summary:

```
curl 'https://api.github.com/repos/awesome-ctf/TCTF2021-Guthib/events?page=1' > repoevents-1.json
curl 'https://api.github.com/repos/awesome-ctf/TCTF2021-Guthib/events?page=2' > repoevents-2.json
curl 'https://api.github.com/repos/awesome-ctf/TCTF2021-Guthib/events?page=3' > repoevents-3.json
curl 'https://api.github.com/repos/awesome-ctf/TCTF2021-Guthib/events?page=4' > repoevents-4.json
less repoevents-4.json
less repoevents-3.json
grep -ho '[a-f0-9]\{40\}' repoevents*.json | sort | uniq
```
