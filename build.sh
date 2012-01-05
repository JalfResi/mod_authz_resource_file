if [ "$OSTYPE" = "linux-gnu" ]; then
{
	sudo apxs2 -c -i -I ./include -I ../authz_resource/include ./src/mod_authz_resource_file.c
#	sudo cp ./src/mod_authz_resource.slo /etc/apache2/mods-available/mod_authz_resource.load
#	echo "Hello linux"
}
else
{
	if [ "$OSTYPE" = "darwin8.0" ]; then
	{
		sudo apxs -c -i -Wc,-g -I ./include -I ../authz_resource/include ./src/mod_authz_resource_file.c
#		sudo cp ./src/mod_authz_resource.slo /usr/local/apache2/modules/mod_authz_resource.so
#		echo "OSX DUDE"
	}
	fi
}
fi
