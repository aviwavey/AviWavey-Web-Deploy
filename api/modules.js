import lms from '../src/LmsRuntime.mjs';
import toolkit from '../src/ToolkitRuntime.mjs';
import {createModuleHandler} from '../src/ModuleDispatch.mjs';
export default createModuleHandler({lms,toolkit});
