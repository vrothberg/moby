package daemon

import (
	"fmt"
	"io"
	"runtime"

	"github.com/docker/docker/container"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/chrootarchive"
	"github.com/docker/docker/pkg/ioutils"
)

// ContainerExport writes the contents of the container to the given
// writer. An error is returned if the container cannot be found.
func (daemon *Daemon) ContainerExport(name string, out io.Writer) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("the daemon on this platform does not support export of a container")
	}

	container, err := daemon.GetContainer(name)
	if err != nil {
		return err
	}

	if container.IsDead() {
		return fmt.Errorf("You cannot export container %s which is Dead", container.ID)
	}

	if container.IsRemovalInProgress() {
		return fmt.Errorf("You cannot export container %s which is being removed", container.ID)
	}

	data, err := daemon.containerExport(container)
	if err != nil {
		return fmt.Errorf("Error exporting container %s: %v", name, err)
	}
	defer data.Close()

	// Stream the entire contents of the container (basically a volatile snapshot)
	if _, err := io.Copy(out, data); err != nil {
		return fmt.Errorf("Error exporting container %s: %v", name, err)
	}
	return nil
}

func (daemon *Daemon) containerExport(container *container.Container) (arch io.ReadCloser, err error) {
	rwLayer, err := daemon.layerStore.GetRWLayer(container.ID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			daemon.layerStore.ReleaseRWLayer(rwLayer)
		}
	}()

	_, err = rwLayer.Mount(container.GetMountLabel())
	if err != nil {
		return nil, err
	}

	uidMaps, gidMaps := daemon.GetUIDGIDMaps()
	archive, err := chrootarchive.Tar(container.BaseFS, &archive.TarOptions{
		Compression: archive.Uncompressed,
		UIDMaps:     uidMaps,
		GIDMaps:     gidMaps,
	}, container.BaseFS)
	if err != nil {
		rwLayer.Unmount()
		return nil, err
	}
	arch = ioutils.NewReadCloserWrapper(archive, func() error {
		err := archive.Close()
		rwLayer.Unmount()
		daemon.layerStore.ReleaseRWLayer(rwLayer)
		return err
	})
	daemon.LogContainerEvent(container, "export")
	return arch, err
}
