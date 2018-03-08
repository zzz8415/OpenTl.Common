// include Fake lib
#r "packages/FAKE/tools/FakeLib.dll"
open Fake

// Properties
let buildDir = FullName "./build/"

let apikey = getBuildParam "apikey"
let version = getBuildParam "version"

Target "Default" (fun _ -> 
   XMLHelper.XmlPokeInnerText "./src/OpenTl.Common/OpenTl.Common.csproj" "/Project/PropertyGroup/Version" version
   XMLHelper.XmlPokeInnerText "./src/OpenTl.Common.Testing/OpenTl.Common.Testing.csproj" "/Project/PropertyGroup/Version" version

   DotNetCli.Restore (fun p -> p)

   CleanDir buildDir
 
   DotNetCli.Build (fun p -> 
   { p with
      Project = "./src/OpenTl.Common/OpenTl.Common.csproj"
      Configuration = "Release"
   })
   
    DotNetCli.Pack (fun p -> 
      { p with
         OutputPath = buildDir
         Project = "./src/OpenTl.Common/OpenTl.Common.csproj"
      })
      
    Paket.Push (fun nugetParams -> 
          { nugetParams with
              ApiKey = apikey
              WorkingDir = buildDir
          }
         )
   
   CleanDir buildDir

   DotNetCli.Build (fun p -> 
      { p with
         Project = "./src/OpenTl.Common.Testing/OpenTl.Common.Testing.csproj"
         Configuration = "Release"
      })

   DotNetCli.Pack (fun p -> 
      { p with
         OutputPath = buildDir
         Project = "./src/OpenTl.Common.Testing/OpenTl.Common.Testing.csproj"
      })
   
   Paket.Push (fun nugetParams -> 
             { nugetParams with
                 ApiKey = apikey
                 WorkingDir = buildDir
             }
            )
)

Target "Default" (fun _ ->
   trace "Hello World from FAKE"
)


// start build
RunTargetOrDefault "Default"