.PHONY: build, submit, clean

build:
	dotnet publish -p:PublishSingleFile=true
	mv bin/Release/*/*/publish/IPK-project2 ipk-sniffer

submit:
	zip -r xsleza26.zip *.cs CHANGELOG.md ipk2-cd.drawio.png \
		IPK-project2.csproj LICENSE Makefile README.md

clean:
	-rm -rf bin obj ipk-sniffer xsleza26.zip
