%JAVA_HOME%\bin\java.exe -jar mjar.jar io/github/jsbxyyx testjar.jar

%JAVA_HOME%\bin\java.exe -agentpath:./libmjar.dll=io/github/jsbxyyx -jar testjar-enc.jar