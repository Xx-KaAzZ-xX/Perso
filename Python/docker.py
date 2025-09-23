import os, json, shutil

class Conteneur(object):
	def __init__(self, container_path):
		super(Conteneur, self).__init__()
		with open(os.path.join(container_path, "config.v2.json"), "r") as f :
			self.config = json.load(f)

		self._name        = self.config.get("Name").replace("/", "")
		self._image_layer = self.config.get("Image").split(":")
		self._image_base  = self.config.get("Config").get("Image")
		# print(self._image_layer)

	def test(self, container_path):
		self._streamconfig = data.get("StreamConfig")
		self._state = data.get("State")
		self._id = data.get("ID")
		self._created = data.get("Created")
		self._managed = data.get("Managed")
		self._path = data.get("Path")
		self._args = data.get("Args")
		self._config = data.get("Config")		
		self._networksettings = data.get("NetworkSettings")
		self._logpath = data.get("LogPath")		
		self._driver = data.get("Driver")
		self._os = data.get("OS")
		self._mountlabel = data.get("MountLabel")
		self._processlabel = data.get("ProcessLabel")
		self._restartcount = data.get("RestartCount")
		self._hasbeenstartedbefore = data.get("HasBeenStartedBefore")
		self._hasbeenmanuallystopped = data.get("HasBeenManuallyStopped")
		self._mountpoints = data.get("MountPoints")
		self._secretreferences = data.get("SecretReferences")
		self._configreferences = data.get("ConfigReferences")
		self._apparmorprofile = data.get("AppArmorProfile")
		self._hostnamepath = data.get("HostnamePath")
		self._hostspath = data.get("HostsPath")
		self._shmpath = data.get("ShmPath")
		self._resolvconfpath = data.get("ResolvConfPath")
		self._seccompprofile = data.get("SeccompProfile")
		self._nonewprivileges = data.get("NoNewPrivileges")
		self._locallogcachemeta = data.get("LocalLogCacheMeta")

class Docker(object):	
	def __init__(self, docker_path=None, system=None):
		super(Docker, self).__init__()
		self.containers = {}
		self.system = system
		if system is not None: 
			self.docker_path = os.path.join(system, "var", "lib", "docker")
		if docker_path is not None : 
			self.docker_path = docker_path

		self.containers_path = os.path.join(self.docker_path, "containers") ### format(container_id)
		self.config_path = os.path.join(self.docker_path, "containers", "{}", "config.v2.json") ### format(container_id)
		
		self.imagedb_path = os.path.join(self.docker_path, "image", "overlay2", "imagedb", "content", "{}", "{}")

		self.mounts = {}
		self.mounts_path = os.path.join(self.docker_path, "image", "overlay2", "layerdb", "mounts")
		self.mount_id_path = os.path.join(self.docker_path, "image", "overlay2", "layerdb", "mounts", "{}", "mount-id")
		self.mount_parent_path = os.path.join(self.docker_path, "image", "overlay2", "layerdb", "mounts", "{}", "parent")

		self.layerdb = {}
		self.layerdb_path = os.path.join(self.docker_path, "image", "overlay2", "layerdb", "sha256")
		self.layerdb_cache_id_path = os.path.join(self.docker_path, "image", "overlay2", "layerdb", "sha256", "{}", "cache-id")
		self.layerdb_diff_path = os.path.join(self.docker_path, "image", "overlay2", "layerdb", "sha256", "{}", "diff")

		self.overlay2_path = os.path.join(self.docker_path, "overlay2", "{}", "diff")

		self.volumes = os.path.join(self.docker_path, "volumes", "{}", "_data")
		self.list_conteneur()
		self.list_layer_db()
		self.list_mount_layer()

	def list_conteneur(self):
		for container_id in os.listdir(self.containers_path):			
			self.containers[self.containers_name(self.config_path.format(container_id))] = container_id

	def list_layer_db(self):
		for layerdb_id_path in os.listdir(self.layerdb_path):
			diff     = self.return_data(self.layerdb_diff_path.format(layerdb_id_path))
			cache_id = self.return_data(self.layerdb_cache_id_path.format(layerdb_id_path))
			self.layerdb[diff] = cache_id

	def list_mount_layer(self):
		for mount_id_path in os.listdir(self.mounts_path):
			_id    = self.return_data(self.mount_id_path.format(mount_id_path))
			self.mounts[mount_id_path] = _id

	def containers_name(self, container_id):
		return self.return_data_json(container_id).get("Name").replace("/", "")

	def containers_image_layer(self, name):
		return self.return_data_json(self.config_path.format(self.containers[name])).get("Image").split(":")

	def containers_image_base(self, name):
		return self.return_data_json(self.config_path.format(self.containers[name])).get("Config").get("Image")

	def containers_mount_points(self, name):
		mount_point = []
		mount_data = self.return_data_json(self.config_path.format(self.containers[name])).get("MountPoints")
		for path in mount_data :
			if mount_data.get(path).get("Source") != "" :
				point = ( mount_data.get(path).get("Source").split("/")[1:],
						  mount_data.get(path).get("Destination").split("/")[1:],
						  0)
			else:
				point = ( [mount_data.get(path).get("Name")],
						  mount_data.get(path).get("Destination").split("/")[1:],
						  1)
			mount_point.append(point)				
		return mount_point

	def rootfs(self, name):
		overlay2 = []
		sha, _id = self.containers_image_layer(name)
		fs = self.return_data_json(self.imagedb_path.format(sha, _id)).get("rootfs")
		if fs.get("type") == "layers":
			for layer in fs.get("diff_ids") :
				overlay2.append(self.layerdb.get(layer))

		overlay2.append(self.mounts[self.containers[name]])
		return overlay2

	def return_data_json(self, file):
		with open(file, "r") as f :
			data = json.load(f)
		return data

	def return_data(self, file):
		with open(file, "r") as f :
			data = f.read()
		return data

	def recover_fs(self, name, destination="./"):
		dest_rep = os.path.join(destination, "service_"+name)

		for elt in self.rootfs(name):
			if os.path.isdir(self.overlay2_path.format(elt)):
				# destination = shutil.copytree(self.overlay2_path.format(elt), dest_rep, dirs_exist_ok=True)
				print(self.overlay2_path.format(elt))
				pass

		for src, dst, typ in self.containers_mount_points(name) :
			if typ == 0 :
				if self.system is not None:
					src = os.path.join(self.system, src)
					dst = os.path.join(dest_rep, dst)
					# destination = shutil.copytree(src, dst, dirs_exist_ok=True)
			elif typ == 1 :
				src = os.path.join(self.docker_path, src)
				dst = os.path.join(dest_rep, dst)
				# destination = shutil.copytree(src, dst, dirs_exist_ok=True)
			
			print(src, dst, typ)
	
	def recover_all(self, destination="./"):
		for name in self.containers.keys() :
			self.recover_fs(name, destination)

	def list_conteneur_name(self):
		for name in self.containers.keys() :
			print(name)

if __name__ == '__main__':
	docker_path = "./docker_bryan/docker"
	# docker_path = "_test_trois"
	docker = Docker(docker_path=docker_path)
	docker.list_conteneur_name()
	# print(docker.containers_mount_points("mysql"))
	# docker.recover_fs("grafana")

