import yaml
import os

with open(os.path.splitext(__file__)[0]+'.yaml') as f:
    api = yaml.safe_load(f.read())

def build_list_method(path, name, config):
    need_args = [(v or dict()).get('alias', k).rstrip('s') for k,v in config.items()][:-1]
    make_path = "'"+path+"'" + (('%('+','.join(need_args)+',)') if need_args else '')
    code = f'''
    def list_{name}(self{", " if need_args else ""}{", ".join(need_args)}, **kwargs):
        path = {make_path}
        return self.get_path(path, **kwargs)
    '''
    print(code)
    
def build_single_get_method(path, name, config):
    need_args =  [(v or dict()).get('alias', k).rstrip('s') for k,v in config.items()][:-1]
    make_path = "'"+path+"'" + (('%('+','.join(need_args)+',)') if need_args else '')
    code = f'''
    def get_{name}(self{", " if need_args else ""}{", ".join(need_args)}, **kwargs):
        path = {make_path}
        return self.get_path(path, **kwargs)'''
    if not need_args:
        code += f'''
    @property
    def {name}(self):
        return self.get_{name}(cache={config.get("cache", True)}, cached={config.get("cache", True)})'''
    print(code)
    

def build_each_get_method(path, name, config, part=None):
    name = name.rstrip('s')
    need_args =  [(v or dict()).get('alias', k).rstrip('s') for k,v in config.items()]
    if part:
        need_args.append(part)
    make_path = "'"+path+"/%s"+("/%s" if part else "")+"'" + (('%('+','.join(need_args)+',)') if need_args else '')
    code = f'''
    def get_{name}{("_"+part) if part else ""}(self{", " if need_args else ""}{", ".join(need_args)}, **kwargs):
        path = {make_path}
        return self.get_path(path, **kwargs)'''
    print(code)
    
def build_create_method(path, name, root, config, part=None):
    name = name.rstrip('s')
    need_args =  [(v or dict()).get('alias', k).rstrip('s') for k,v in root.items()]
    if not part:
        need_args = need_args[:-1]
    make_path = "'"+path+("/%s" if part else "")+"'" + (('%('+','.join(need_args)+',)') if need_args else '')
    require_args = [k for k,v in (config or dict()).items() if v=="require"]
    make_paras = ['paras = dict()']
    for arg in require_args:
        need_args.append(arg)
        make_paras.append(f'paras["{arg}"] = {arg}')
    opt_args = [(k,"'"+v+"'" if isinstance(v, str) else str(v)) for k,v in (config or dict()).items() if v!="require"]
    for k,v in opt_args:
        need_args.append(f'{k}={None if v[1]=="!" else v}')
        make_paras.append(f'paras["{k}"] = ' + (f"({k} or {v[2:-1]})" if v[1]=='!' else f"{k}"))
    make_paras = '\n'.join(['        '+p for p in make_paras])
    code = f'''
    def create_{name}{("_"+part) if part else ""}(self{", " if need_args else ""}{", ".join(need_args)}, **kwargs):
        path = {make_path}
{make_paras}
        return self.create_path(path, paras, **kwargs)'''
    print(code)    

def build_update_method(path, name, root, config, part=None):
    name = name.rstrip('s')
    need_args =  [(v or dict()).get('alias', k).rstrip('s') for k,v in root.items()]
    if part:
        need_args.append(part)
    make_path = "'"+path+"/%s"+("/%s" if part else "")+"'" + (('%('+','.join(need_args)+',)') if need_args else '')
    code = f'''
    def update_{name}{("_"+part) if part else ""}(self{", " if need_args else ""}{", ".join(need_args)}, **kwargs):
        path = {make_path}
        return self.update_path(path, [{', '.join(["'"+c+"'" for c in config])}], **kwargs)'''
    print(code)
   

def build_exists_method(path, name, config):
    name = name.rstrip('s')
    need_args =  [(v or dict()).get('alias', k).rstrip('s') for k,v in config.items()]
    make_path = "'"+path+"/%s'" + (('%('+','.join(need_args)+',)') if need_args else '')
    code = f'''
    def exists_{name}(self{", " if need_args else ""}{", ".join(need_args)}, **kwargs):
        path = {make_path}
        return self.exists_path(path, **kwargs)'''
    print(code)
    
def build_delete_method(path, name, config, part=None):
    name = name.rstrip('s')
    need_args =  [(v or dict()).get('alias', k).rstrip('s') for k,v in config.items()]
    if part:
        need_args.append(part)
    make_path = "'"+path+"/%s"+("/%s" if part else "")+"'" + (('%('+','.join(need_args)+',)') if need_args else '')
    code = f'''
    def delete_{name}{("_"+part) if part else ""}(self{", " if need_args else ""}{", ".join(need_args)}, **kwargs):
        path = {make_path}
        return self.delete_path(path, **kwargs)'''
    print(code)
    
    
def build_api_method(root, path, config):
    full_path = '/'+'/%s/'.join([k for k in root.keys()]+[path])
    stem = '_'.join([(v or dict()).get('alias', k).rstrip('s') for k,v in root.items()]+[(config or dict()).get('alias', path)])
    eroot = root.copy()
    eroot[path] = config
    for key, value in config.items():
        if key == 'get':
            build_single_get_method(full_path, stem, eroot)
        elif key == 'list':
            build_list_method(full_path, stem, eroot)
        elif key == 'create':
            build_create_method(full_path, stem, eroot, value)
        elif key == 'each':
            for ekey, evalue in value.items():
                if ekey == 'get':
                    build_each_get_method(full_path, stem, eroot)
                elif ekey == 'update':
                    build_update_method(full_path, stem, eroot, evalue)
                elif ekey == 'exists':
                    build_exists_method(full_path, stem, eroot)
                elif ekey == 'delete':
                    build_delete_method(full_path, stem, eroot)
        elif key == 'parts':
            for pkey, pvalue in value.items():
                for ekey, evalue in pvalue.items():
                    if ekey == 'get':
                        build_each_get_method(full_path, stem, eroot, pkey)
                    elif ekey == 'delete':
                        build_delete_method(full_path, stem, eroot, pkey)
                    elif ekey == 'update':
                        build_update_method(full_path, stem, eroot, evalue, pkey)
                    elif ekey == 'create':
                        build_create_method(full_path, stem, eroot, evalue, pkey)
        elif key == 'contains':
            for ekey, evalue in value.items():
                build_api_method(eroot, ekey, evalue)
    
for path, config in api.items():
    build_api_method({}, path, config)

