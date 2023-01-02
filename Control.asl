//By MrLette, based off Wangler auto-start/load remover. Anyone is free to host, fork or modify the following code.

state("Control_DX11", "DX11") { }
state("Control_DX12", "DX12") { }

startup
{
    vars.gameTarget = new SigScanTarget(3,
        "48 8B 05 ????????",  // mov  rax, [Control_DX1#.exe+????????]
        "48 8B 48 30",        // mov  rcx, [rax+30]
        "80 B9 ???????? 00"); // cmp  byte ptr [rcx+?], 00

    vars.inputManagerTarget = new SigScanTarget(10, "48 89 86 ?? ?? 00 00 48 89 35"); // signature to get InputManager instance pointer
	vars.completeMissionFunctionAddressSig = new SigScanTarget(0, "49 8B CE 84 C0 74 54 48 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 90 49 8B CE"); //Signature to get CompleteMission function (search for "CompleteMission" string Xref in IDA, offset is 0x5246E3 in 0.96)
	vars.getInstanceSig = new SigScanTarget(5, "33 C0 48 8D 0D ?? ?? ?? ?? 48 8B 04 08 C3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 4C 24 08"); //Signature to coreflow::Systems::getInstance(), used to get the pointer to coreflow::Systems::sm_instances
	vars.completeObjectiveFunctionAddressSig = new SigScanTarget(1, "57 41 56 41 57 48 83 EC 20 45 0F B6 F9 49 8B F8 4C 8B F2 48 8B F1 E8");//Siganture to the function called by CompleteStep 
	vars.FreeMemory = (Action<Process>)(p =>
    {
        p.FreeMemory((IntPtr)vars.hookBytecodeCave);
		p.FreeMemory((IntPtr)vars.objectiveHookBytecodeCave);
    });

	settings.Add("intro_subsplits", false, "Detailed subsplits for first 3 missions");
	settings.CurrentDefaultParent = "intro_subsplits";
		settings.Add("M01_subsplits", false, "Welcome to the Oldest House (Service Weapon, Astral Plane, & Cleanse Central)");
		settings.Add("M02_subsplits", false, "Unknown Caller (Dead Letters, Floppy Disk, Launch Trial, Mail Room, Motel, & Hotline)");
		//settings.Add("M03_subsplits", false, "Directorial Override/Merry Chase (Ventilation Skip aka split when starting Merry Chase)");
		settings.Add("M04_subsplits", false, "Old Boys Club Parapsychology subsplit");
	settings.CurrentDefaultParent = null;

	settings.Add("boss_subsplits", false, "Boss fight subsplits for all bosses category");

	settings.Add("dlc_support", false, "DLC Mission subsplits");
	settings.CurrentDefaultParent = "dlc_support";
		settings.Add("expeditions_dlc", false, "Expeditions"); //also todo....
		settings.Add("foundation_dlc", false, "The Foundation");
		settings.Add("awe_dlc", false, "AWE");
	settings.CurrentDefaultParent = null;

	//so these are a bit of a hack as they just add a few more checks to the isLoading action
	//I'm aware that livesplit can read/simulate the in-game timer so I may add that in the future (might be needed for expeditions even)
	//leaving as is for now because of the game's timing rules
	settings.Add("timer_ext", false, "Extended timer options (currently not allowed for submitted runs!!)");
	settings.CurrentDefaultParent = "timer_ext";
		settings.Add("time_out_pause_menu", false, "Time out pause menu screen (need a state for loadout menu");
		settings.Add("time_out_photo_mode", false, "Time out photo mode screen");
		settings.Add("time_out_cutscenes", false, "Time out cutscenes (any instance where playerControlEnabled is false)");
	settings.CurrentDefaultParent = null;

	settings.Add("debug_spew", false, "debug spew");
	//print("startup: refreshRate " + refreshRate.ToString());
}

init
{
    vars.isFoundationPatch = modules.First().ModuleMemorySize >= 20418560; // foundation patch exe size, may break in the future

    var module = modules.First();
    var inputStr = module.ModuleName == "Control_DX11.exe" ? "input_rmdwin7_f.dll" : "input_rmdwin10_f.dll";
	var rlStr = module.ModuleName == "Control_DX11.exe" ? "rl_rmdwin7_f.dll" : "rl_rmdwin10_f.dll";

    var scanner = new SignatureScanner(game, module.BaseAddress, module.ModuleMemorySize);
    var gameScan = scanner.Scan((SigScanTarget)vars.gameTarget);

    var inputModule = modules.Single(m => m.ModuleName == inputStr);
    var imScanner = new SignatureScanner(game, inputModule.BaseAddress, inputModule.ModuleMemorySize);
    var imScan = imScanner.Scan((SigScanTarget)vars.inputManagerTarget);

	var rlModule = modules.Single(m => m.ModuleName == rlStr);
	var rlScanner = new SignatureScanner(game, rlModule.BaseAddress, rlModule.ModuleMemorySize);
	
    var offset = game.ReadValue<int>(gameScan);
    var imOffset = game.ReadValue<int>(imScan);
    var loadingOffset = game.ReadValue<int>(gameScan + 10);

    if (vars.isFoundationPatch)
        loadingOffset += 3;

    Thread.Sleep(2500); // Give the game a chance to initialize..

    // Boolean for loading
    vars.isLoading = new MemoryWatcher<bool>(new DeepPointer(module.ModuleName, (int)((long)(gameScan + offset + 4) - (long)module.BaseAddress), 0x30, loadingOffset));

    // ClientState hash
    vars.state = new MemoryWatcher<uint>(new DeepPointer(module.ModuleName, (int)((long)(gameScan + offset + 4) - (long)module.BaseAddress), 0x30, vars.isFoundationPatch ? 0x138 : 0x1A8));

    // InputManager.playerControlEnabled
    vars.playerControlEnabled = new MemoryWatcher<bool>(new DeepPointer(inputModule.ModuleName, (int)((long)(imScan + imOffset + 4) - (long)inputModule.BaseAddress), vars.isFoundationPatch ? 0x7D : 0x8D));


	vars.completeMissionFunctionAddress = scanner.Scan((SigScanTarget)vars.completeMissionFunctionAddressSig);
	if (vars.completeMissionFunctionAddress == IntPtr.Zero)
		throw new Exception("Can't find completeMission function address");
	vars.completeMissionFunctionAddress = (IntPtr)vars.completeMissionFunctionAddress;
	var jmpInstructionSize = 12; //x64 creates 12 bytes instructions, 10 bytes to mov the addr to rax then 2 bytes for jmp'ing to rax
	var overridenBytesForTrampoline = 14; //See the 4 original instructions below 
	
	//Original code copied (comment based on 0.96) :
	//	0x49 ,0x8B, 0xCE, 							mov rcx,r14
	//	0x84, 0xC0,       							test al,al
	//	0x74, 0x54,		  							je Control_DX11.exe+52474A
	//	0x48, 0x8D, 0x95, 0xC0, 0x05, 0x00, 0x00 	lea rdx,[rbp+000005C0]
	vars.originalMissionCompleteFunctionCode = game.ReadBytes((IntPtr)vars.completeMissionFunctionAddress, overridenBytesForTrampoline);
	
	//Bytecode that executes the code overrided by the trampoline jmp + sets a boolean to true and stores mission GID in our newly allocated memory when called
	var missionCompleteHookBytecode = new List<byte> {0x58}; //pop rax (restore saved rax)
	missionCompleteHookBytecode.AddRange((byte[])vars.originalMissionCompleteFunctionCode); //Adding original code
	missionCompleteHookBytecode.AddRange(new byte[] {0x8B, 0x41, 0x10}); //mov eax,[rcx+10]
	missionCompleteHookBytecode.AddRange(new byte[] {0x89, 0x05, 0x20, 0x00, 0x00, 0x00}); //mov [rip+32],eax Storing current mission GID
	missionCompleteHookBytecode.AddRange(new byte[] {0xC6, 0x05, 0x18, 0x00, 0x00, 0x00, 0x01}); //mov byte ptr[rip+24],0x01 (our instruction to set our boolean to true on execution)
	missionCompleteHookBytecode.AddRange(new byte[(jmpInstructionSize * 2) + 1 + 4] ); //We need 2 jumps, one for each branch of the "test al,al" instruction copied from the original code + 1 byte for our bool storage + 4 byte for mission GID storage

	vars.hookBytecodeCave = game.AllocateMemory(missionCompleteHookBytecode.Count);
	vars.isMissionCompletedAddress = (IntPtr)vars.hookBytecodeCave + missionCompleteHookBytecode.Count - 5;
	vars.isMissionCompleted = new MemoryWatcher<bool>(vars.isMissionCompletedAddress);

	vars.completeObjectiveFunctionAddress = scanner.Scan((SigScanTarget)vars.completeObjectiveFunctionAddressSig);
	if (vars.completeObjectiveFunctionAddress == IntPtr.Zero)
		throw new Exception("Can't find completeStep function address");
	var overridenBytesForObjectiveTrampoline = 12;
	//Original code copied (comment based on 0.96) :
	//Control_DX11.exe+3EFD8B - 41 56                 - push r14
	//Control_DX11.exe+3EFD8D - 41 57                 - push r15
	//Control_DX11.exe+3EFD8F - 48 83 EC 20           - sub rsp,20
	//Control_DX11.exe+3EFD93 - 45 0FB6 F9            - movzx r15d,r9l

	vars.originalObjectiveCompleteFunctionCode = game.ReadBytes((IntPtr)vars.completeObjectiveFunctionAddress, overridenBytesForObjectiveTrampoline);
	
	//Bytecode that executes the code overrided by the trampoline jmp + stores latest objective hash in our newly allocated memory when called
	var objectiveCompleteHookBytecode = new List<byte>((byte[])vars.originalObjectiveCompleteFunctionCode);
	objectiveCompleteHookBytecode.AddRange(new byte[] {0x49, 0x8b, 0x38}); //mov  rdi,QWORD PTR [r8]
	objectiveCompleteHookBytecode.AddRange(new byte[] {0x48, 0x89, 0x3D, 0x0C, 0x00, 0x00, 0x00}); //mov QWORD PTR [rip+0xc],rdi
	objectiveCompleteHookBytecode.AddRange(new byte[jmpInstructionSize + 8] ); //We need one jump + 8 bytes for storing objective hash

	vars.objectiveHookBytecodeCave = game.AllocateMemory(objectiveCompleteHookBytecode.Count);
	vars.latestObjectiveHashAddress = (IntPtr)vars.objectiveHookBytecodeCave + objectiveCompleteHookBytecode.Count - 8;
	vars.latestObjectiveHash = new MemoryWatcher<UInt64>(vars.latestObjectiveHashAddress);

	game.Suspend();
	try {		
		//Writing hook function into memory
		game.WriteBytes((IntPtr)vars.hookBytecodeCave, missionCompleteHookBytecode.ToArray());
		game.WriteJumpInstruction((IntPtr)vars.hookBytecodeCave + missionCompleteHookBytecode.Count - ((jmpInstructionSize * 2) + 5), (IntPtr)vars.completeMissionFunctionAddress + overridenBytesForTrampoline); //Set jump back to inside if on original function (je not executed)
		game.WriteJumpInstruction((IntPtr)vars.hookBytecodeCave + missionCompleteHookBytecode.Count - (jmpInstructionSize + 5), (IntPtr)vars.completeMissionFunctionAddress + 0x54 + 7); //Set jump back to outside if on original function (je executed)
		game.WriteBytes((IntPtr)vars.isMissionCompletedAddress, new byte[] {0x00}); //Make sure our boolean starts set to false
		game.WriteBytes((IntPtr)vars.hookBytecodeCave + 7, new byte[] {0x23}); //Patching the je offset from original code to point to our second jmp
		
		//Placing trampoline on original function
		game.WriteBytes((IntPtr)vars.completeMissionFunctionAddress, new byte[] {0x50}); //push rax
		game.WriteJumpInstruction((IntPtr)vars.completeMissionFunctionAddress + 1, (IntPtr)vars.hookBytecodeCave); //injecting the 12 bytes trampoline jmp to our hook codecave
		game.WriteBytes((IntPtr)vars.completeMissionFunctionAddress + 1 + jmpInstructionSize, new byte[] {0x90}); //nop the last byte
		
		//Writing hook function into memory
		game.WriteBytes((IntPtr)vars.objectiveHookBytecodeCave, objectiveCompleteHookBytecode.ToArray());
		game.WriteJumpInstruction((IntPtr)vars.objectiveHookBytecodeCave + objectiveCompleteHookBytecode.Count - (jmpInstructionSize + 8), (IntPtr)vars.completeObjectiveFunctionAddress + overridenBytesForObjectiveTrampoline); //Set jump back to outside if on original function
		game.WriteBytes((IntPtr)vars.latestObjectiveHashAddress, new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
		
		//Placing trampoline on original function
		game.WriteJumpInstruction((IntPtr)vars.completeObjectiveFunctionAddress, (IntPtr)vars.objectiveHookBytecodeCave); //injecting the 12 bytes trampoline jmp to our hook codecave
	}
	catch {
		vars.FreeMemory(game);
		game.WriteBytes((IntPtr)vars.completeMissionFunctionAddress, (byte[])vars.originalMissionCompleteFunctionCode); //Restore original bytecode
		game.WriteBytes((IntPtr)vars.completeObjectiveFunctionAddress, (byte[])vars.originalObjectiveCompleteFunctionCode); //Restore original bytecode
		throw new Exception("Something went wrong when placing hooks");
	}
	finally {
		game.Resume();
	}
	
	var sm_instancesptr = rlScanner.Scan((SigScanTarget)vars.getInstanceSig);
	var sm_instances_offset = game.ReadValue<int>(sm_instancesptr);
	vars.sm_instances = sm_instancesptr + 4 + sm_instances_offset;

	vars.autoEndNext = false; //probs need to clear this elsewhere too
}

update
{
	vars.state.Update(game);
	vars.isLoading.Update(game);

	if (settings.StartEnabled || settings.SplitEnabled) {
		vars.playerControlEnabled.Update(game);
	}
	
	if (settings.SplitEnabled) {
		vars.isMissionCompleted.Update(game);
		vars.latestObjectiveHash.Update(game);
	}
	
	if (vars.state.Current != vars.state.Old || vars.playerControlEnabled.Current != vars.playerControlEnabled.Old || vars.isLoading.Current != vars.isLoading.Old || vars.isMissionCompleted.Current != vars.isMissionCompleted.Old || vars.latestObjectiveHash.Current != vars.latestObjectiveHash.Old) {
		print("vars.state " + ((UInt64)vars.state.Current).ToString("X") + " - vars.playerControlEnabled " + (vars.playerControlEnabled.Current).ToString() + " - vars.isLoading " + (vars.isLoading.Current).ToString() + " - vars.isMissionCompleted " + (vars.isMissionCompleted.Current).ToString());
	}
	if (vars.latestObjectiveHash.Current != vars.latestObjectiveHash.Old) {
		print("vars.latestObjectiveHash Old " + ((IntPtr)vars.latestObjectiveHash.Old).ToString("X") + " - Current " + ((IntPtr)vars.latestObjectiveHash.Current).ToString("X"));
	}

	//delete me
	if (settings["debug_spew"]) { //spits the latest objectiveHash into dbgView
		print("vars.latestObjectiveHash " + ((IntPtr)vars.latestObjectiveHash.Current).ToString("X"));
		//print("refreshRate: " refreshRate.ToString());
	}
}

exit
{
    timer.IsGameTimePaused = true;
}

/*
start
{
    return vars.state.Current == 0xE89FFD52 && !vars.playerControlEnabled.Old && vars.playerControlEnabled.Current;
}

isLoading
{
    return vars.isLoading.Current || vars.state.Current == 0x469239DF || vars.state.Current == 0xD439EBF1 || vars.state.Current == 0xB5C73550 || vars.state.Current == 0x63C25A55 || vars.state.Current == 0;
}
*/

//[5384] at Line 225, Col 9: Syntax error, expected: init, exit, update, start, split, isLoading, gameTime, reset, startup, shutdown, onStart, onSplit, onReset
onStart
{ //clear these now so our first subsplit won't get ignored
	if (vars.isMissionCompleted.Current)
		game.WriteBytes((IntPtr)vars.isMissionCompletedAddress, new byte[] {0x00});
	if (vars.latestObjectiveHash.Current != 0)
		game.WriteBytes((IntPtr)vars.latestObjectiveHashAddress, new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
}

start
{
	if (settings["dlc_support"])
	{//dlc autostart mayb..?
		if (settings["expeditions_dlc"]) { //add later
		}
		else if (vars.isFoundationPatch)
		{
			if (settings["foundation_dlc"]) {
				if (vars.latestObjectiveHash.Current != (UInt64)vars.latestObjectiveHash.Old && (UInt64)vars.latestObjectiveHash.Current == 0x381EE2B72AE34051) {
					return true;
				}
			}
			else if (settings["awe_dlc"]) {
				if (vars.state.Current == 0xE89FFD52 && vars.isLoading.Old && !vars.isLoading.Current) { //well obviously this works but causes a lot of false-starts, would be better if we were able to check the map being loaded, or active mission (displayed on HUD)
					return true;
				}
			}
		}
	}
	else if (vars.state.Current == 0xE89FFD52 && !vars.playerControlEnabled.Old && vars.playerControlEnabled.Current)
	{
		return true;
	}

	return false;
}

isLoading
{
	if (settings["timer_ext"]) {
		if (settings["time_out_cutscenes"] && !vars.playerControlEnabled.Current)
			return true;
	}

	switch ((UInt64)vars.state.Current)
	{ //ugly code ik
		case 0xEAE3EF29: //pause menu open (no state for loadout menu unfortunately...)
			if (settings["dlc_support"] && settings["expeditions_dlc"]) //expeditions runs use the IGT timer
				return true;
			return (settings["timer_ext"] && settings["time_out_pause_menu"]);
			
		case 0x1CC77BAA: //in photo mode
			if (settings["dlc_support"] && settings["expeditions_dlc"]) //expeditions runs use the IGT timer
				return true;
			return (settings["timer_ext"] && settings["time_out_photo_mode"]);

		case 0x469239DF: //ClientStatePlatformServicesLogon
		case 0xD439EBF1: //ClientStateStart
		case 0xB5C73550: //ClientStateSplashScreen
		case 0x63C25A55: //ClientStateMainMenu
		case 0: //null state i guess
			return true;
		default:
			break;
	}

	return vars.isLoading.Current;
}

shutdown
{
	game.Suspend();
	vars.FreeMemory(game);
	game.WriteBytes((IntPtr)vars.completeMissionFunctionAddress, (byte[])vars.originalMissionCompleteFunctionCode); //Restore original bytecode
	game.WriteBytes((IntPtr)vars.completeObjectiveFunctionAddress, (byte[])vars.originalObjectiveCompleteFunctionCode); //Restore original bytecode
	game.Resume();
}

split
{

	if (vars.latestObjectiveHash.Current != vars.latestObjectiveHash.Old)
	{
		if (!vars.autoEndNext && vars.latestObjectiveHash.Current == 0x1C34375B7D39C051 && vars.latestObjectiveHash.Old != 0 /*== 0x2A351C86227EC051*/) { //can't check for that because bureau alerts...
			print("catching autoEnd");
			vars.autoEndNext = true;
			refreshRate = 1; //HACKHACKHACK: i know this is really bad, but because we track the final cutscene with playerControlEnabled, which sometimes updates later than the objective, we need to wait a second so it doesn't split on the projector
			return false;
		}
	}

	if (vars.autoEndNext)
	{
		if (refreshRate == 1) {
			refreshRate = 66.6666666666667; //ok so APPARENTLY it actually defaults to this value on startup.. lol
			return false;
		}

		if (vars.autoEndNext && !vars.playerControlEnabled.Current && vars.playerControlEnabled.Old) {
			print("triggering end split");
			vars.autoEndNext = false;
			game.WriteBytes((IntPtr)vars.latestObjectiveHashAddress, new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
			return true;
		}
		//return false;
	}

	if (vars.isMissionCompleted.Current && !vars.isMissionCompleted.Old)
	{
		game.WriteBytes((IntPtr)vars.isMissionCompletedAddress, new byte[] {0x00});
		//This whole RPM heavy part has to be done here rather than init as I witnessed some pointer changes during gameplay.
		//Some cache system could be implemented with a MemoryWatcher, but the following code should be fast enough on any computer able to run that game anyway.
	
		//Here we are looking into the global sm_instances pool to find the mission manager component, from which we will be able to get the list of all game missions
		var componentStateArray = game.ReadValue<IntPtr>(game.ReadValue<IntPtr>((IntPtr)vars.sm_instances + 8));
		while (game.ReadValue<int>(componentStateArray + 8) != 0x6871eafd) //This is some kind of checksum equal to "MissionManagerSingletonComponentState"
			componentStateArray += 24;
		var missionManagerSingletonComponentState = game.ReadValue<IntPtr>(componentStateArray + 16);
		var missionArrayOffset = game.ReadValue<int>(game.ReadValue<IntPtr>(missionManagerSingletonComponentState + 8) + 20);
		var missionArray = game.ReadValue<IntPtr>(missionManagerSingletonComponentState + missionArrayOffset + 88);
		var missionArraySize = game.ReadValue<int>(missionManagerSingletonComponentState + missionArrayOffset + 96);
		
		//Here we iterate into our mission array and try to match the mission globalID with the one we got from the mission completion hook
		var missionGID = game.ReadValue<int>((IntPtr)vars.isMissionCompletedAddress + 1);
		
		print("missionGID " + ((int)missionGID).ToString("X") + " - missionArraySize " + missionArraySize.ToString());
		if (missionGID == 0x529729E) { //special case for "Endgame" mission, to stop it from splitting on the credits
			return false;
		}
		else if (missionGID == 0x1F0E75B7 || missionGID == 0x7D958C2) { //another special case for Self Reflection & Captive Audience, since skips have been found that allow completing the mission without starting it
			return true;
		}

		int i = 0;
		while (game.ReadValue<int>(missionArray + 4) != missionGID) {
			if (i > missionArraySize) {
				print("Mission not found in missionArray (invalid or undefined), skipping");
				return false;
			}
			missionArray += 47 * 8;
			i++;
		}

		var triggerName = game.ReadString(missionArray + 0xC0, 15);
		if (triggerName == "OnAlertAppeared") {
			print("Bureau alert, skipping");
			//maybe reset objective hash here??
			//game.WriteBytes((IntPtr)vars.latestObjectiveHashAddress, vars.latestObjectiveHash.Old);
			return false;
		}
		return true;
	}
	else if (vars.isMissionCompleted.Current && vars.isMissionCompleted.Old) { //This happens at least once at the end of a run, because split isn't called (we end on dylan intercation) but mission still complete when getting back to bureau, our boolean will be stuck on true and break the autosplitter until game restart.
		game.WriteBytes((IntPtr)vars.isMissionCompletedAddress, new byte[] {0x00});
	}

	if (vars.latestObjectiveHash.Current != vars.latestObjectiveHash.Old)
	{

		if (settings["intro_subsplits"])
		{
			/*
			should check for the current mission gid?
			maybe it'd be a better idea to check against the old as well, incase this causes any random splits later
			could also probably check the expected inputEnabled state as well just to be totally safe
			*/

			switch ((UInt64)vars.latestObjectiveHash.Current)
			{ // maybe this should be checking against the old objectiveHash as well, incase this causes any random splits down the line....
				case 0x29FECD336DD44051:	//Welcome to the Oldest House - Follow the Board's instructions to complete the Astral Plane Challenge (astral plane)
				case 0x10469758BD9F0051:	//Welcome to the Oldest House - Proceed Further Into the Bureau (leaving astral plane)
				case 0x3132CD8588D24051:	//Welcome to the Oldest House - Cleanse the Control Point
					return (bool)settings["M01_subsplits"];

				case 0x367A9559D4A9C051:	//Unknown Caller - Navigate through the Communications Dept. (cleansed dead letters cp)
				case 0x13607262FE258051:	//Unknown Caller - Use Launch to complete the Astral Plane challenge
				case 0x14D67242479FC051:	//Unknown Caller - Proceed through the Communications Dept.
				//everything below might be skippable in the future
				case 0x35806926DF63C051:	//Unknown Caller - Traverse the Oceanview Motel
				case 0x16BDA8576AB68051:	//Unknown Caller - Pick up the Hotline
				case 0x21D1ECA6BEAA4051:	//Unknown Caller - Speak with Emily
					return (bool)settings["M02_subsplits"];

				//case 0x2CA177693EB94051:	//Directorial Override - Find Ahti the janitor
				////case 0x22F74A8FE8D0C051:	//Merry Chase - Use evade to complete the Astral Plane challenge
				//case 0x152DB5CD65554051:	//Directorial Override - Speak with Emily
				//	return (bool)settings["M03_subsplits"];
				case 0x31689A1F87650051: //Parapsych CP in OBC
					return (bool)settings["M04_subsplits"];
				default:
					break;
			}
		}

		if (settings["boss_subsplits"])
		{ //all of these might be really bad because bureau alerts.. we need to figure out how to filter those objective hashes out
			switch ((UInt64)vars.latestObjectiveHash.Current)
			{
				case 0x8F00E1590A64051: //tommasi
				case 0xB3B1007E000C051: //salvador (Use Levitate to Complete the Astral Plane Challenge blah blah)
				case 0x2CF792EBAC1EC051: //fisrt set of runaways complete 
				case 0xEA86841EC930051: //former 2
				case 0x1F39DF767722C051: //tommasi 2
				case 0x33E8A13A04098051: //mold-1
					return true;
				default:
					break;
			}
		}

		if (settings["dlc_support"])
		{
			/*if (settings["expeditions_dlc"])
			{
				switch ((UInt64)vars.latestObjectiveHash.Current)
				{
					case 3:
						return true;
					default:
						break;
				}
			}*/

			//these probably totally break inbounds or with an alternate route/order
			if (vars.isFoundationPatch)
			{
				
				if (settings["foundation_dlc"])
				{
					switch ((UInt64)vars.latestObjectiveHash.Current)
					{
						//THE FOUNDATION
						case 0x119FA53302A50051: //Investigate the Nail or whatever 
						//case 0x1B0C6E0946F10051: //Explore the Astral Plane Challenge x1?
						//case 0x34218EFD2D6DC051:  //Complete the Astral Plane Challenge
							return true;
						//THE NAIL
						case 0x3A696D83C0970051: //Complete the Ritual in the Warehouse
						case 0xD44A7C450B00051: //Warehouse complete
						case 0x5A4718B582F8051:  //Complete the ritual in the Collapsed Department
						case 0x216E530535514051: //Collapsed department done ig UNKNOWN WTF WTF WTF
						case 0x195619844FFE0051:  //Collapsed department done ? (Complete ritual in the Deep Cavern is left)
						case 0x38384013E28B0051: //site gamma + canyon rim (collapsed dept done)
						
						case 0x1D7253050CBA4051: //Reach the Canyon Rim + Complete the ritual in the Deep Cavern
						//case 0x2507179EE174C051: //Reach the Canyon Rim + Complete the ritual in the Deep Cavern (UNKNOWN WTF WTF WTF ?) (OK NO THIS ONE IS BAD NO THANK YOU LOL)
						case 0x2A91E334C2250051: //Reach the Canyon Rim (deep cavern done)
						case 0x6BE65486A6E4051: ////Complete the ritual in the Astral Plane (Foundation / Canyon Rim)
							return true;
						//THE PYRAMID
						//case 0x3E5E8A543CA30051: //Reach the bottom of the Nail (actually using this to finish The Nail split)
						case 0x1804BDFBEC60051: //Defeat marshall
						case 0x16EC5F1B76790051: //Cleanse the Nail
						case 0x8D52E0CDCD80051: //Return to crossroads
							return true;
						default:
							break;
					}
				}

				if (settings["awe_dlc"])
				{
					switch ((UInt64)vars.latestObjectiveHash.Current)
					{
						//A DARK PLACE
						case 0x2FEC2B16318A4051: //Traverse the Oceanview Motel
						case 0x1864139D5AF9C051: //Explore the Investigations Sector x2
						//case 0x1C5065A615590051: //Activate the lights to defeat the creature ?
						case 0x342F2F4201EDC051: //Explore the Investigations Sector x3
							return true;
						//THE THIRD THING
						case 0x146499859B788051: //dunno what objective name this has but it came after defeating hartman in the AWE transit bay
						case 0x303B38B8A0AF4051:  //Find Hartman in the Fra Mauro AWE area
						case 0x18B8DF5CCE514051: //Activate the lights to defeat hartman
						case 0x2BBFEED1A464C051: //Return to the Active Investigations
							return true;
						//IT'S HAPPENING AGAIN
						case 0x1FA976B3B7C84051: //Traverse the Oceanview Motel
						case 0x30B841738945C051: //motel finished
						case 0x33673D226AC78051: //Defeat Hartman
							return true;
						default:
							break;
					}
				}
			}
		}
	}

	//if (settings["dlc_support"] && vars.isFoundationPatch && vars.latestObjectiveHash.Current != vars.latestObjectiveHash.Old)
	if (settings["dlc_support"] && vars.isFoundationPatch && !vars.playerControlEnabled.Current && vars.playerControlEnabled.Old)
	{ //auto end for dlcs ?
		if (settings["foundation_dlc"] && (UInt64)vars.latestObjectiveHash.Current == 0x8D52E0CDCD80051) //Return to crossroads
		{ //The Foundation
			game.WriteBytes((IntPtr)vars.latestObjectiveHashAddress, new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
			return true;
			//vars.autoEndNext = true;
			//return false;
		}
		else if (settings["awe_dlc"] && (UInt64)vars.latestObjectiveHash.Current == 0x33673D226AC78051)
		{ //AWE
			//game.WriteBytes((IntPtr)vars.latestObjectiveHashAddress, new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
			//return true;
			vars.autoEndNext = true;
			return false;
		}
	}

	return false;
}

/*
    Used state hashes (FNV-1a):
    0x469239DF = ClientStatePlatformServicesLogon
    0xD439EBF1 = ClientStateStart
    0xB5C73550 = ClientStateSplashScreen
    0x63C25A55 = ClientStateMainMenu
    0xE89FFD52 = ClientStateInGame

	//new state hashes (i do not know the names of these)
	0x8F99476B = in fake credits (After Polaris)
	0xEAE3EF29 = pause menu open
	0x1CC77BAA = in photo mode
*/

/*
	Used/useful objective hashes
	0x3FDF050CEAC10051 //Polaris - Cleanse the siphons
	0xC31E52063870051 //Polaris - Reach Polaris (credits starting)
	0x1C34375B7D39C051 //Take Control - Turn off the Slide Projector (updated at Reach Dylan)

	0x529729E //Mision hash for Take Control/Endgame
	0x1F0E75B7 //Mission hash for Self Reflection

	Rest of the objective subsplits are commented above

	Objective hashes for AWE DLC
	//notes below are the reported values with the respective objective string (so the hashes are probably for the objective before)
	//confusing im sure but oh well
	//also these r probably gonna break on route change
	//A Dark Place
	0xFB9DC88B3600051 //Take an Elevator to the Investigations Sector -> Explore the Investigations Sector (after elevator opens) ?
	0x2FEC2B16318A4051 //Traverse the Oceanview Motel
	0x1864139D5AF9C051 //Explore the Investigations Sector x2
	0x1C5065A615590051 //Activate the lights to defeat the creature
	0x342F2F4201EDC051 //Explore the Investigations Sector x3
	0x1C5065A615590051  //Speak with Langston on the intercom

	//The Third Thing
	0x1299EBD8D992C051 //Find Hartman in the Fra Mauro AWE area + Find Hartman in the Eagle Limited AWE area ?
	0x146499859B788051 //dunno what objective name this has but it came after defeating hartman in the AWE transit bay
	0x303B38B8A0AF4051 //Find Hartman in the Fra Mauro AWE area
	0x18B8DF5CCE514051 //Activate the lights to defeat hartman
	0x2BBFEED1A464C051 //Return to the Active Investigations
	
	//It's Happening Again
	[7684] vars.latestObjectiveHash Old 21E364FE7E814051 - Current 1FA976B3B7C84051
	0x1FA976B3B7C84051 //Traverse the Oceanview Motel
	0x30B841738945C051 //finish motel
	0x33673D226AC78051 //Defeat Hartman
	0xC11D5D05BEEC051 //hartman defeated

*/


