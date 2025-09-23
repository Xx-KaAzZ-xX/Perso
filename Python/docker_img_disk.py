from dfvfs.analyzer import analyzer
from dfvfs.lib import definitions
from dfvfs.path import factory
from dfvfs.volume import tsk_volume_system
from dfvfs.resolver import resolver
import json, os, pickle

def offset_to_ag_block(offset):
  ag = offset // (ag_block_count*block_size)
  block = int((offset%(ag_block_count*block_size))/block_size)
  return ag, block

class DiskImage(object):
	"""docstring for DiskImage"""
	def __init__(self, img_path):
		super(DiskImage, self).__init__()
		self.path_spec = factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_OS, location=img_path)
		self.partition_table = []
		self.getImageType()
		self.getVolume()

	def getImageType(self):
		MediaImageTypeIndicators = analyzer.Analyzer.GetStorageMediaImageTypeIndicators(self.path_spec)

		if MediaImageTypeIndicators != []:
			MediaImageTypeIndicators = MediaImageTypeIndicators[0]
		else: 
			MediaImageTypeIndicators = ""

		if MediaImageTypeIndicators == "EWF" :
			self.path_spec = factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_EWF, parent=self.path_spec)
		elif MediaImageTypeIndicators == "QCOW" :
			self.path_spec = factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_QCOW, parent=self.path_spec)
		elif MediaImageTypeIndicators == "VHDI" :
			self.path_spec = factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_VHDI, parent=self.path_spec)
		elif MediaImageTypeIndicators == "VMDK" :
			self.path_spec = factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_VMDK, parent=self.path_spec)
		elif MediaImageTypeIndicators == "" :
			self.path_spec = factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_RAW, parent=self.path_spec)

	def getVolume(self):
		VolumeSystemTypeIndicators = analyzer.Analyzer.GetVolumeSystemTypeIndicators(self.path_spec)
		if VolumeSystemTypeIndicators == ['TSK_PARTITION'] :
			self.path_spec = factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_TSK_PARTITION, parent=self.path_spec)
			volume_system = tsk_volume_system.TSKVolumeSystem()
			volume_system.Open(self.path_spec)
			for volume in volume_system.volumes:
				data = (volume.identifier, hex(volume.extents[0].offset), volume.extents[0].size)
				self.partition_table.append(data)

	def printVolume(self):
		print("{} partition(s) a / ont été découverte(s) :".format(len(self.partition_table)))
		for name, start, size in self.partition_table : 
			print("\t+ {} :".format(name))
			print("\t\t- Start offset : {}".format(start))
			print(("\t\t- Size : {}".format(size)))

	def getFsType(self):
		part_type = analyzer.Analyzer.GetFileSystemTypeIndicators(self.path_spec)
		if part_type != [] :
			return part_type[0]
		else: 
			return ""

	def selectPartition(self, part):
		self.partition = None
		self.path_spec.location = "/{}".format(part)
		part_type = self.getFsType()
		if part_type == "XFS" :
			self.partition = factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_XFS, location="/", parent=self.path_spec)
		elif part_type == "NTFS" :
			self.partition = factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_NTFS, location="/", parent=self.path_spec)

	def lsRoot(self):
		root = []
		if self.partition is not None :
			self.partition.location = "/"
			file_entry = resolver.Resolver.OpenFileEntry(self.partition)
			for sub in file_entry.sub_file_entries :
				root.append(sub.name)
		return root

	def listdir(self, rep_path):
		list_rep = []
		if self.partition is not None :
			self.partition.location = rep_path
			file_entry = resolver.Resolver.OpenFileEntry(self.partition)
			for sub in file_entry.sub_file_entries :
				list_rep.append(sub.name)
		return list_rep

	def read(self, file_path):
		data = ""
		if self.partition is not None :
			if self.partition.TYPE_INDICATOR == "XFS" :
				self.partition.location = file_path
				file_entry = resolver.Resolver.OpenFileEntry(self.partition)
				file_object = file_entry.GetFileObject()
				data =  file_object.read().decode()
				file_object.close()				
		return data

	def recover_copy(self, source_path, dest_path):
		if self.partition is not None :
			if self.partition.TYPE_INDICATOR == "XFS" :
				self.partition.location = source_path

				file_entry = resolver.Resolver.OpenFileEntry(self.partition)
				if file_entry is None :
					extractFile = open(dest_path.replace(":", "_"),'wb')
					extractFile.close()
				elif file_entry.IsDirectory() :
					for sub in file_entry.sub_file_entries :
						if source_path[-1] == "/" :
							source_rep = source_path + sub.name
						else : 
							source_rep = source_path + "/" + sub.name
						if dest_path[-1] == "/" :
							dest_rep = dest_path + sub.name
						else : 
							dest_rep = dest_path + "/" + sub.name
						if sub.IsDirectory() :
							os.makedirs(dest_rep, exist_ok=True)
						self.recover_copy(source_rep, dest_rep)
				elif file_entry.IsFile() :
					file_object = file_entry.GetFileObject()
					extractFile = open(dest_path,'wb')
					if file_entry.size != 0 :
						data = file_object.read(4096)
						while data:
							extractFile.write(data)
							data = file_object.read(4096)
					extractFile.close()
					file_object.close()
				elif file_entry.IsLink() :
					extractFile = open(dest_path,'wb')
					extractFile.write(file_entry.link.encode())
					extractFile.close()
				elif file_entry.IsLocked() :
					print("Non traité IsLocked", source_path)
				elif file_entry.IsPipe() :
					print("Non traité IsPipe", source_path)
				elif file_entry.IsRoot() :
					print("Non traité", source_path)
				elif file_entry.IsSocket() :
					file_object = file_entry.GetFileObject()
					extractFile = open(dest_path.replace(":", "_"),'wb')
					if file_entry.size != 0 :
						data = file_object.read(4096)
						while data:
							extractFile.write(data)
							data = file_object.read(4096)
					extractFile.close()
				elif file_entry.IsVirtual() :
					print("Non traité IsVirtual", source_path)

	def test(self):
		self.path_spec.location = "/p2"
		source_path = "/var/lib/docker/volumes/4dbbd0371f7bec4823bdfb07fb4dcad75efbb3c85f7289f5c0e87549ee99c7c2/_data/node-alert.log"
		source_path = "/var/lib/docker/containers/abdb200f9a1ac60ad2ee405105b1658a388a59fbf2989e0cdaf6d3dff0e0e5c9/abdb200f9a1ac60ad2ee405105b1658a388a59fbf2989e0cdaf6d3dff0e0e5c9-json.log"
		self.partition = factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_XFS, location=source_path, parent=self.path_spec)
		# self.partition = factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_XFS, inode=0xc0399f27, parent=self.path_spec)
		# print(dir(self.partition))
		file_entry = resolver.Resolver.OpenFileEntry(self.partition)
		print(dir(file_entry))
		print()
		if file_entry.IsDirectory() :
			for sub in file_entry.sub_file_entries :
				test = sub.GetStatAttribute()
				print(sub.name, hex(test.inode_number))
		elif file_entry.IsFile() :
			file_size = 0
			extents = file_entry.GetFileObject()._fsxfs_file_entry
			print(extents.number_of_extents)
			print(hex(extents.get_extent(376)[0]))
			print(extents)
			print(dir(extents))

			# for extent in extents:
			# 	file_size += extent.size
			# 	print(hex(extent.offset), extent.size)
		
		# source_path = "/var/lib/docker/containers/abdb200f9a1ac60ad2ee405105b1658a388a59fbf2989e0cdaf6d3dff0e0e5c9/abdb200f9a1ac60ad2ee405105b1658a388a59fbf2989e0cdaf6d3dff0e0e5c9-json.log"
		# if self.partition is not None :
		# 	if self.partition.TYPE_INDICATOR == "XFS" :
		# 		self.partition.inode = 68
				# self.partition.location = source_path
			# 	print(dir(self.partition))
			# 	print(self.partition.location)

				# file_entry = resolver.Resolver.OpenFileEntry(self.partition)
				# for sub in file_entry.sub_file_entries :
				# 	print(sub.name)
				# print(dir(file_entry))
				# print(file_entry.link)
			# 	print(dir(parent))
class Docker(object):	
	def __init__(self, img_path):
		super(Docker, self).__init__()
		self.img_path = img_path
		self.img = DiskImage(img_path)

	def printVolume(self) :
		self.img.printVolume()

	def selectAll(self):
		for partition in self.img.partition_table :
			self.selectPartition(partition[0])

	def selectPartition(self, partition):
		self.system = False
		self.mounts = {}
		self.layerdb = {}
		self.containers = {}
		self.img.selectPartition(partition)
		self.docker_fs = self.img_path+f".{partition}"+".fs"
		self.docker_layer_db = self.img_path+f".{partition}"+".layer_db"
		self.docker_mounts = self.img_path+f".{partition}"+".mounts"
		ls_root = self.img.lsRoot()
		if "etc" and "run" and "sys" and "root" and "usr" in  ls_root :
			self.system = True
			print("Partition {} système de type Linux identifié.".format(partition))
			self.docker_path           = "/var/lib/docker/"
			self.containers_path       = "/var/lib/docker/containers/"
			self.config_path           = "/var/lib/docker/containers/{}/config.v2.json"
			self.imagedb_path          = "/var/lib/docker/image/overlay2/imagedb/content/{}/{}/"
			self.mounts_path            = "/var/lib/docker/image/overlay2/layerdb/mounts"
			self.mount_id_path	       = "/var/lib/docker/image/overlay2/layerdb/mounts/{}/mount-id"
			self.mount_parent_path     = "/var/lib/docker/image/overlay2/layerdb/mounts/{}/parent"
			self.layerdb_path      	   = "/var/lib/docker/image/overlay2/layerdb/sha256"
			self.layerdb_cache_id_path = "/var/lib/docker/image/overlay2/layerdb/sha256/{}/cache-id"
			self.layerdb_diff_path     = "/var/lib/docker/image/overlay2/layerdb/sha256/{}/diff"
			self.overlay2_path         = "/var/lib/docker/overlay2/{}/diff/"
			self.volumes_path          = "/var/lib/docker/volumes/{}/_data/"
		elif "Program Files" and "Program Files (x86)" and "Users" and "Windows" in ls_root :	
			print("Partition {} système de type Windows identifié.".format(partition))
		elif ls_root == []:
			print("Partition {} aucune donnée localisée".format(partition))
		else: 
			print("Partition {} partition Data identifiée.".format(partition))

		if self.system :
			if not os.path.isfile(self.docker_fs):
				self.list_conteneur()
			else :
				if os.path.getsize(self.docker_fs) == 0 :
					self.list_conteneur()
				else: 
					with open(self.docker_fs, "rb") as f :
						self.containers = pickle.load(f)

			if not os.path.isfile(self.docker_layer_db):
				self.list_layer_db()
			else :
				if os.path.getsize(self.docker_layer_db) == 0 :
					self.list_layer_db()
				else: 
					with open(self.docker_layer_db, "rb") as f :
						self.layerdb = pickle.load(f)

			if not os.path.isfile(self.docker_mounts):
				self.list_mount_layer()
			else :
				if os.path.getsize(self.docker_mounts) == 0 :
					self.list_mount_layer()
				else: 
					with open(self.docker_mounts, "rb") as f :
						self.mounts = pickle.load(f)

	def list_conteneur(self):
		for container_id in self.img.listdir(self.containers_path):		
			self.containers[self.containers_name(self.config_path.format(container_id))] = container_id
		with open(self.docker_fs, "wb") as f :
			pickle.dump(self.containers, f)

	def list_layer_db(self):
		for layerdb_id_path in self.img.listdir(self.layerdb_path):
			diff     = self.return_data(self.layerdb_diff_path.format(layerdb_id_path))
			cache_id = self.return_data(self.layerdb_cache_id_path.format(layerdb_id_path))
			self.layerdb[diff] = cache_id
		with open(self.docker_layer_db, "wb") as f :
			pickle.dump(self.layerdb, f)

	def list_mount_layer(self):
		for mount_id_path in self.img.listdir(self.mounts_path):
			_id = self.return_data(self.mount_id_path.format(mount_id_path))
			self.mounts[mount_id_path] = _id
		with open(self.docker_mounts, "wb") as f :
			pickle.dump(self.mounts, f)

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
				point = ( mount_data.get(path).get("Source"),
						  mount_data.get(path).get("Destination"),
						  0)
			else:
				point = ( mount_data.get(path).get("Name"),
						  mount_data.get(path).get("Destination"),
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
		return json.loads(self.img.read(file))

	def return_data(self, file):
		return self.img.read(file)

	def recover_all(self, destination="./"):
		for name in self.containers.keys() :
			self.recover_fs(name, destination)

	def list_conteneur_name(self):
		for name in self.containers.keys() :
			print(name)

	def recover_fs(self, name, destination="./"):
		if destination[-1] == "/" :
			dest_rep = destination + "service_"+name
		else : 
			dest_rep = destination + "/" + "service_"+name
		os.makedirs(dest_rep, exist_ok=True)
		print("Récupération du service : {}".format(name))
		for elt in self.rootfs(name):
			print("\t Couche : {}".format(elt))
			self.img.recover_copy(self.overlay2_path.format(elt), dest_rep)

		mounts = self.containers_mount_points(name)
		if mounts != [] :
			print("Récupération des points de montage du service : {}".format(name))
			for src, dst, typ in mounts :
				if typ == 0 :
					dst = dest_rep + dst
				elif typ == 1 :
					src = self.volumes_path.format(src)
					dst = dest_rep + dst								
				print("\t Type : {}".format(typ))
				print("\t Source : {}".format(src))
				print("\t Destination : {}".format(dst))
				self.img.recover_copy(src, dst)

if __name__ == '__main__' :
	# docker = Docker(test)
	# docker.selectPartition("p2")
	# docker.recover_all("./mkp1_docker")

	# test = r"H:\az_8540_AR_302518-23_RH.E01.e01"
	# docker = Docker(test)
	# docker.selectPartition("p1")
	# docker.recover_all("./mkp2_docker")

	test = r"F:\\hdd0.E01"
	test = DiskImage(test)
	# test.printVolume()
	test.selectPartition("p2")
	# print(dir(resolver.Resolver))
	# source_path = "/var/lib/docker/volumes/4dbbd0371f7bec4823bdfb07fb4dcad75efbb3c85f7289f5c0e87549ee99c7c2/_data/node-alert.log"
	test.test()
	# test.recover_copy(source_path, "F:/carv/mkp1/node")
