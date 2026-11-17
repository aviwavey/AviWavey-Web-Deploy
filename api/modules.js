import lms from '../src/LmsRuntime.mjs';
import toolkit from '../src/ToolkitRuntime.mjs';
import {createModuleHandler} from '../src/ModuleDispatch.mjs';
import cloud9 from '../src/Cloud9Runtime.mjs';
import {createCloud9Dispatch} from '../src/Cloud9Dispatch.mjs';
export default createCloud9Dispatch({cloud9,other:createModuleHandler({lms,toolkit})});
