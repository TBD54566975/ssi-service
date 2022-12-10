package storage

import (
	"github.com/pkg/errors"
	"strings"
	"sync"
)

// MemoryDB is an in memory implementation of ServiceStorage that is safe for concurrent use.
type MemoryDB struct {
	maps sync.Map
}

func (f *MemoryDB) Update(namespace string, key string, updater Updater) ([]byte, error) {
	v, err := f.Read(namespace, key)
	if err != nil {
		return nil, err
	}
	if err = updater.Validate(v); err != nil {
		return nil, err
	}
	updatedV, err := updater.Update(v)
	if err != nil {
		return nil, err
	}
	if err = f.Write(namespace, key, updatedV); err != nil {
		return nil, err
	}
	return updatedV, nil
}

func (f *MemoryDB) ReadPrefix(namespace, prefix string) (map[string][]byte, error) {
	if namespace == "" {
		return nil, nil
	}
	m, _ := f.maps.LoadOrStore(namespace, &sync.Map{})
	r := make(map[string][]byte)
	m.(*sync.Map).Range(func(key, value any) bool {
		if strings.HasPrefix(key.(string), prefix) {
			r[key.(string)] = value.([]byte)
		}
		return true
	})
	return r, nil
}

func (f *MemoryDB) ReadAllKeys(namespace string) ([]string, error) {
	if namespace == "" {
		return nil, nil
	}
	m, _ := f.maps.LoadOrStore(namespace, &sync.Map{})
	r := make([]string, 0, 10)
	m.(*sync.Map).Range(func(key, value any) bool {
		r = append(r, key.(string))
		return true
	})
	return r, nil
}

func (f *MemoryDB) UpdateValueAndOperation(namespace, key string, updater Updater, opNamespace, opKey string, rUpdater ResponseSettingUpdater) ([]byte, []byte, error) {
	updatedV, err := f.Update(namespace, key, updater)
	if err != nil {
		return nil, nil, err
	}

	op, err := f.Read(opNamespace, opKey)
	if err != nil {
		return nil, nil, err
	}
	if err = rUpdater.Validate(op); err != nil {
		return nil, nil, err
	}
	rUpdater.SetUpdatedResponse(updatedV)
	opUpdated, err := rUpdater.Update(op)
	if err != nil {
		return nil, nil, err
	}
	if err = f.Write(opNamespace, opKey, opUpdated); err != nil {
		return nil, nil, err
	}
	return updatedV, opUpdated, nil
}

func (f *MemoryDB) Type() Storage {
	return "in memory test storage"
}

func (f *MemoryDB) Close() error {
	return nil
}

func (f *MemoryDB) Write(namespace, key string, value []byte) error {
	if namespace == "" {
		return errors.New("namespace required")
	}
	if key == "" {
		return errors.New("key required")
	}

	b, _ := f.maps.LoadOrStore(namespace, &sync.Map{})
	b.(*sync.Map).Store(key, value)
	return nil
}

func (f *MemoryDB) Read(namespace, key string) ([]byte, error) {
	if namespace == "" {
		// This is what the bolt implementation does.
		return nil, nil
	}
	if key == "" {
		return nil, errors.New("key required")
	}
	m, ok := f.maps.Load(namespace)
	if !ok {
		return nil, nil
	}

	v, _ := m.(*sync.Map).Load(key)
	if v == nil {
		return nil, nil
	}
	return v.([]byte), nil
}

func (f *MemoryDB) ReadAll(namespace string) (map[string][]byte, error) {
	if namespace == "" {
		return nil, nil
	}
	m, _ := f.maps.LoadOrStore(namespace, &sync.Map{})
	r := make(map[string][]byte)
	m.(*sync.Map).Range(func(key, value any) bool {
		r[key.(string)] = value.([]byte)
		return true
	})
	return r, nil
}

func (f *MemoryDB) Delete(namespace, key string) error {
	if namespace == "" {
		return errors.New("namespace required")
	}
	if key == "" {
		return errors.New("key required")
	}

	b, ok := f.maps.Load(namespace)
	if !ok {
		return errors.Errorf("namespace<%s> does not exist", namespace)
	}
	b.(*sync.Map).Delete(key)
	return nil
}

func (f *MemoryDB) DeleteNamespace(namespace string) error {
	if namespace == "" {
		return errors.New("namespace required")
	}
	if _, loaded := f.maps.LoadAndDelete(namespace); !loaded {
		return errors.Errorf("could not delete namespace<%s>", namespace)
	}
	return nil
}
