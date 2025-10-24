//===--- StringComparison.swift -------------------------------------*- swift -*-===//
//
// This source file is part of the Swift.org open source project
//
// Copyright (c) 2014 - 2021 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See https://swift.org/LICENSE.txt for license information
// See https://swift.org/CONTRIBUTORS.txt for the list of Swift project authors
//
//===----------------------------------------------------------------------===//

////////////////////////////////////////////////////////////////////////////////
// WARNING: This file is manually generated from .gyb template and should not
// be directly modified. Instead, make changes to StringComparison.swift.gyb and run
// scripts/generate_harness/generate_harness.py to regenerate this file.
////////////////////////////////////////////////////////////////////////////////

//
// Test String iteration performance over a variety of workloads, languages,
// and symbols.
//

import TestsUtils

extension String {
  func lines() -> [String] {
    return self.split(separator: "\n").map { String($0) }
  }
}
public let benchmarks: [BenchmarkInfo] = [
  BenchmarkInfo(
    name: "StringComparison_ascii",
    runFunction: run_StringComparison_ascii,
    tags: [.validation, .api, .String],
    setUpFunction: { blackHole(workload_ascii) }
  ),
  BenchmarkInfo(
    name: "StringComparison_latin1",
    runFunction: run_StringComparison_latin1,
    tags: [.validation, .api, .String],
    setUpFunction: { blackHole(workload_latin1) },
		legacyFactor: 2
  ),
  BenchmarkInfo(
    name: "StringComparison_fastPrenormal",
    runFunction: run_StringComparison_fastPrenormal,
    tags: [.validation, .api, .String],
    setUpFunction: { blackHole(workload_fastPrenormal) },
		legacyFactor: 10
  ),
  BenchmarkInfo(
    name: "StringComparison_slowerPrenormal",
    runFunction: run_StringComparison_slowerPrenormal,
    tags: [.validation, .api, .String],
    setUpFunction: { blackHole(workload_slowerPrenormal) },
		legacyFactor: 10
  ),
  BenchmarkInfo(
    name: "StringComparison_nonBMPSlowestPrenormal",
    runFunction: run_StringComparison_nonBMPSlowestPrenormal,
    tags: [.validation, .api, .String],
    setUpFunction: { blackHole(workload_nonBMPSlowestPrenormal) },
		legacyFactor: 10
  ),
  BenchmarkInfo(
    name: "StringComparison_emoji",
    runFunction: run_StringComparison_emoji,
    tags: [.validation, .api, .String],
    setUpFunction: { blackHole(workload_emoji) },
		legacyFactor: 4
  ),
  BenchmarkInfo(
    name: "StringComparison_abnormal",
    runFunction: run_StringComparison_abnormal,
    tags: [.validation, .api, .String],
    setUpFunction: { blackHole(workload_abnormal) },
		legacyFactor: 20
  ),
  BenchmarkInfo(
    name: "StringComparison_zalgo",
    runFunction: run_StringComparison_zalgo,
    tags: [.validation, .api, .String],
    setUpFunction: { blackHole(workload_zalgo) },
		legacyFactor: 25
  ),
  BenchmarkInfo(
    name: "StringComparison_longSharedPrefix",
    runFunction: run_StringComparison_longSharedPrefix,
    tags: [.validation, .api, .String],
    setUpFunction: { blackHole(workload_longSharedPrefix) }
  ),

  BenchmarkInfo(
    name: "StringHashing_ascii",
    runFunction: run_StringHashing_ascii,
    tags: [.validation, .api, .String],
    setUpFunction: { blackHole(workload_ascii) }
  ),
  BenchmarkInfo(
    name: "StringHashing_latin1",
    runFunction: run_StringHashing_latin1,
    tags: [.validation, .api, .String],
    setUpFunction: { blackHole(workload_latin1) },
		legacyFactor: 2
  ),
  BenchmarkInfo(
    name: "StringHashing_fastPrenormal",
    runFunction: run_StringHashing_fastPrenormal,
    tags: [.validation, .api, .String],
    setUpFunction: { blackHole(workload_fastPrenormal) },
		legacyFactor: 10
  ),
  BenchmarkInfo(
    name: "StringHashing_slowerPrenormal",
    runFunction: run_StringHashing_slowerPrenormal,
    tags: [.validation, .api, .String],
    setUpFunction: { blackHole(workload_slowerPrenormal) },
		legacyFactor: 10
  ),
  BenchmarkInfo(
    name: "StringHashing_nonBMPSlowestPrenormal",
    runFunction: run_StringHashing_nonBMPSlowestPrenormal,
    tags: [.validation, .api, .String],
    setUpFunction: { blackHole(workload_nonBMPSlowestPrenormal) },
		legacyFactor: 10
  ),
  BenchmarkInfo(
    name: "StringHashing_emoji",
    runFunction: run_StringHashing_emoji,
    tags: [.validation, .api, .String],
    setUpFunction: { blackHole(workload_emoji) },
		legacyFactor: 4
  ),
  BenchmarkInfo(
    name: "StringHashing_abnormal",
    runFunction: run_StringHashing_abnormal,
    tags: [.validation, .api, .String],
    setUpFunction: { blackHole(workload_abnormal) },
		legacyFactor: 20
  ),
  BenchmarkInfo(
    name: "StringHashing_zalgo",
    runFunction: run_StringHashing_zalgo,
    tags: [.validation, .api, .String],
    setUpFunction: { blackHole(workload_zalgo) },
		legacyFactor: 25
  ),

  BenchmarkInfo(
    name: "NormalizedIterator_ascii",
    runFunction: run_StringNormalization_ascii,
    tags: [.validation, .String],
    setUpFunction: { blackHole(workload_ascii) }
  ),
  BenchmarkInfo(
    name: "NormalizedIterator_latin1",
    runFunction: run_StringNormalization_latin1,
    tags: [.validation, .String],
    setUpFunction: { blackHole(workload_latin1) },
		legacyFactor: 2
  ),
  BenchmarkInfo(
    name: "NormalizedIterator_fastPrenormal",
    runFunction: run_StringNormalization_fastPrenormal,
    tags: [.validation, .String],
    setUpFunction: { blackHole(workload_fastPrenormal) },
		legacyFactor: 10
  ),
  BenchmarkInfo(
    name: "NormalizedIterator_slowerPrenormal",
    runFunction: run_StringNormalization_slowerPrenormal,
    tags: [.validation, .String],
    setUpFunction: { blackHole(workload_slowerPrenormal) },
		legacyFactor: 10
  ),
  BenchmarkInfo(
    name: "NormalizedIterator_nonBMPSlowestPrenormal",
    runFunction: run_StringNormalization_nonBMPSlowestPrenormal,
    tags: [.validation, .String],
    setUpFunction: { blackHole(workload_nonBMPSlowestPrenormal) },
		legacyFactor: 10
  ),
  BenchmarkInfo(
    name: "NormalizedIterator_emoji",
    runFunction: run_StringNormalization_emoji,
    tags: [.validation, .String],
    setUpFunction: { blackHole(workload_emoji) },
		legacyFactor: 4
  ),
  BenchmarkInfo(
    name: "NormalizedIterator_abnormal",
    runFunction: run_StringNormalization_abnormal,
    tags: [.validation, .String],
    setUpFunction: { blackHole(workload_abnormal) },
		legacyFactor: 20
  ),
  BenchmarkInfo(
    name: "NormalizedIterator_zalgo",
    runFunction: run_StringNormalization_zalgo,
    tags: [.validation, .String],
    setUpFunction: { blackHole(workload_zalgo) },
		legacyFactor: 25
  ),
]

let workload_ascii: Workload! = Workload.ascii

let workload_latin1: Workload! = Workload.latin1

let workload_fastPrenormal: Workload! = Workload.fastPrenormal

let workload_slowerPrenormal: Workload! = Workload.slowerPrenormal

let workload_nonBMPSlowestPrenormal: Workload! = Workload.nonBMPSlowestPrenormal

let workload_emoji: Workload! = Workload.emoji

let workload_abnormal: Workload! = Workload.abnormal

let workload_zalgo: Workload! = Workload.zalgo

let workload_longSharedPrefix: Workload! = Workload.longSharedPrefix


@inline(never)
public func run_StringComparison_ascii(_ n: Int) {
  let workload: Workload = workload_ascii
  let tripCount = workload.tripCount
  let payload = workload.payload
  for _ in 1...tripCount*n {
    for s1 in payload {
      for s2 in payload {
        blackHole(s1 < s2)
      }
    }
  }
}

@inline(never)
public func run_StringComparison_latin1(_ n: Int) {
  let workload: Workload = workload_latin1
  let tripCount = workload.tripCount
  let payload = workload.payload
  for _ in 1...tripCount*n {
    for s1 in payload {
      for s2 in payload {
        blackHole(s1 < s2)
      }
    }
  }
}

@inline(never)
public func run_StringComparison_fastPrenormal(_ n: Int) {
  let workload: Workload = workload_fastPrenormal
  let tripCount = workload.tripCount
  let payload = workload.payload
  for _ in 1...tripCount*n {
    for s1 in payload {
      for s2 in payload {
        blackHole(s1 < s2)
      }
    }
  }
}

@inline(never)
public func run_StringComparison_slowerPrenormal(_ n: Int) {
  let workload: Workload = workload_slowerPrenormal
  let tripCount = workload.tripCount
  let payload = workload.payload
  for _ in 1...tripCount*n {
    for s1 in payload {
      for s2 in payload {
        blackHole(s1 < s2)
      }
    }
  }
}

@inline(never)
public func run_StringComparison_nonBMPSlowestPrenormal(_ n: Int) {
  let workload: Workload = workload_nonBMPSlowestPrenormal
  let tripCount = workload.tripCount
  let payload = workload.payload
  for _ in 1...tripCount*n {
    for s1 in payload {
      for s2 in payload {
        blackHole(s1 < s2)
      }
    }
  }
}

@inline(never)
public func run_StringComparison_emoji(_ n: Int) {
  let workload: Workload = workload_emoji
  let tripCount = workload.tripCount
  let payload = workload.payload
  for _ in 1...tripCount*n {
    for s1 in payload {
      for s2 in payload {
        blackHole(s1 < s2)
      }
    }
  }
}

@inline(never)
public func run_StringComparison_abnormal(_ n: Int) {
  let workload: Workload = workload_abnormal
  let tripCount = workload.tripCount
  let payload = workload.payload
  for _ in 1...tripCount*n {
    for s1 in payload {
      for s2 in payload {
        blackHole(s1 < s2)
      }
    }
  }
}

@inline(never)
public func run_StringComparison_zalgo(_ n: Int) {
  let workload: Workload = workload_zalgo
  let tripCount = workload.tripCount
  let payload = workload.payload
  for _ in 1...tripCount*n {
    for s1 in payload {
      for s2 in payload {
        blackHole(s1 < s2)
      }
    }
  }
}

@inline(never)
public func run_StringComparison_longSharedPrefix(_ n: Int) {
  let workload: Workload = workload_longSharedPrefix
  let tripCount = workload.tripCount
  let payload = workload.payload
  for _ in 1...tripCount*n {
    for s1 in payload {
      for s2 in payload {
        blackHole(s1 < s2)
      }
    }
  }
}


@inline(never)
public func run_StringHashing_ascii(_ n: Int) {
  let workload: Workload = Workload.ascii
  let tripCount = workload.tripCount
  let payload = workload.payload
  for _ in 1...tripCount*n {
    for str in payload {
      blackHole(str.hashValue)
    }
  }
}

@inline(never)
public func run_StringHashing_latin1(_ n: Int) {
  let workload: Workload = Workload.latin1
  let tripCount = workload.tripCount
  let payload = workload.payload
  for _ in 1...tripCount*n {
    for str in payload {
      blackHole(str.hashValue)
    }
  }
}

@inline(never)
public func run_StringHashing_fastPrenormal(_ n: Int) {
  let workload: Workload = Workload.fastPrenormal
  let tripCount = workload.tripCount
  let payload = workload.payload
  for _ in 1...tripCount*n {
    for str in payload {
      blackHole(str.hashValue)
    }
  }
}

@inline(never)
public func run_StringHashing_slowerPrenormal(_ n: Int) {
  let workload: Workload = Workload.slowerPrenormal
  let tripCount = workload.tripCount
  let payload = workload.payload
  for _ in 1...tripCount*n {
    for str in payload {
      blackHole(str.hashValue)
    }
  }
}

@inline(never)
public func run_StringHashing_nonBMPSlowestPrenormal(_ n: Int) {
  let workload: Workload = Workload.nonBMPSlowestPrenormal
  let tripCount = workload.tripCount
  let payload = workload.payload
  for _ in 1...tripCount*n {
    for str in payload {
      blackHole(str.hashValue)
    }
  }
}

@inline(never)
public func run_StringHashing_emoji(_ n: Int) {
  let workload: Workload = Workload.emoji
  let tripCount = workload.tripCount
  let payload = workload.payload
  for _ in 1...tripCount*n {
    for str in payload {
      blackHole(str.hashValue)
    }
  }
}

@inline(never)
public func run_StringHashing_abnormal(_ n: Int) {
  let workload: Workload = Workload.abnormal
  let tripCount = workload.tripCount
  let payload = workload.payload
  for _ in 1...tripCount*n {
    for str in payload {
      blackHole(str.hashValue)
    }
  }
}

@inline(never)
public func run_StringHashing_zalgo(_ n: Int) {
  let workload: Workload = Workload.zalgo
  let tripCount = workload.tripCount
  let payload = workload.payload
  for _ in 1...tripCount*n {
    for str in payload {
      blackHole(str.hashValue)
    }
  }
}


@inline(never)
public func run_StringNormalization_ascii(_ n: Int) {
  let workload: Workload = Workload.ascii
  let tripCount = workload.tripCount
  let payload = workload.payload
  for _ in 1...tripCount*n {
    for str in payload {
      str._withNFCCodeUnits { cu in
        blackHole(cu)
      }
    }
  }
}

@inline(never)
public func run_StringNormalization_latin1(_ n: Int) {
  let workload: Workload = Workload.latin1
  let tripCount = workload.tripCount
  let payload = workload.payload
  for _ in 1...tripCount*n {
    for str in payload {
      str._withNFCCodeUnits { cu in
        blackHole(cu)
      }
    }
  }
}

@inline(never)
public func run_StringNormalization_fastPrenormal(_ n: Int) {
  let workload: Workload = Workload.fastPrenormal
  let tripCount = workload.tripCount
  let payload = workload.payload
  for _ in 1...tripCount*n {
    for str in payload {
      str._withNFCCodeUnits { cu in
        blackHole(cu)
      }
    }
  }
}

@inline(never)
public func run_StringNormalization_slowerPrenormal(_ n: Int) {
  let workload: Workload = Workload.slowerPrenormal
  let tripCount = workload.tripCount
  let payload = workload.payload
  for _ in 1...tripCount*n {
    for str in payload {
      str._withNFCCodeUnits { cu in
        blackHole(cu)
      }
    }
  }
}

@inline(never)
public func run_StringNormalization_nonBMPSlowestPrenormal(_ n: Int) {
  let workload: Workload = Workload.nonBMPSlowestPrenormal
  let tripCount = workload.tripCount
  let payload = workload.payload
  for _ in 1...tripCount*n {
    for str in payload {
      str._withNFCCodeUnits { cu in
        blackHole(cu)
      }
    }
  }
}

@inline(never)
public func run_StringNormalization_emoji(_ n: Int) {
  let workload: Workload = Workload.emoji
  let tripCount = workload.tripCount
  let payload = workload.payload
  for _ in 1...tripCount*n {
    for str in payload {
      str._withNFCCodeUnits { cu in
        blackHole(cu)
      }
    }
  }
}

@inline(never)
public func run_StringNormalization_abnormal(_ n: Int) {
  let workload: Workload = Workload.abnormal
  let tripCount = workload.tripCount
  let payload = workload.payload
  for _ in 1...tripCount*n {
    for str in payload {
      str._withNFCCodeUnits { cu in
        blackHole(cu)
      }
    }
  }
}

@inline(never)
public func run_StringNormalization_zalgo(_ n: Int) {
  let workload: Workload = Workload.zalgo
  let tripCount = workload.tripCount
  let payload = workload.payload
  for _ in 1...tripCount*n {
    for str in payload {
      str._withNFCCodeUnits { cu in
        blackHole(cu)
      }
    }
  }
}



struct Workload {
  static let n = 100

  let name: String
  let payload: [String]
  var scaleMultiplier: Double

  init(name: String, payload: [String], scaleMultiplier: Double = 1.0) {
    self.name = name
    self.payload = payload
    self.scaleMultiplier = scaleMultiplier
  }

  var tripCount: Int {
    return Int(Double(Workload.n) * scaleMultiplier)
  }

  static let ascii = Workload(
    name: "ASCII",
    payload: """
      woodshed
      lakism
      gastroperiodynia
      afetal
      Casearia
      ramsch
      Nickieben
      undutifulness
      decorticate
      neognathic
      mentionable
      tetraphenol
      pseudonymal
      dislegitimate
      Discoidea
      criminative
      disintegratory
      executer
      Cylindrosporium
      complimentation
      Ixiama
      Araceae
      silaginoid
      derencephalus
      Lamiidae
      marrowlike
      ninepin
      trihemimer
      semibarbarous
      heresy
      existence
      fretless
      Amiranha
      handgravure
      orthotropic
      Susumu
      teleutospore
      sleazy
      shapeliness
      hepatotomy
      exclusivism
      stifler
      cunning
      isocyanuric
      pseudepigraphy
      carpetbagger
      unglory
      """.lines(),
      scaleMultiplier: 0.25
  )

  static let latin1 = Workload(
    name: "Latin1",
    payload: """
      café
      résumé
      caférésumé
      ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º
      1+1=3
      ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹
      ¡¢£¤¥¦§¨©ª«¬­®
      »¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍ
      ÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãä
      åæçèéêëìíîïðñò
      ÎÏÐÑÒÓÔÕÖëìíîïðñò
      óôõö÷øùúûüýþÿ
      123.456£=>¥
      123.456
      """.lines(),
      scaleMultiplier: 1/2
  )
  static let fastPrenormal = Workload(
    name: "FastPrenormal",
    payload: """
      ĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥ
      ĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸ
      ĹĺĻļĽľĿŀŁłŃńŅņŇňŉŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲ
      ųŴŵŶŷŸŹźŻżŽžſƀƁƂƃƄƅƆ
      ƇƈƉƊƋƌƍƎƏƐƑƒƓƔƕƖƗƘƙƚƛƜƝƞƟƠơƢƣƤƥƦƧƨƩƪƫƬƭƮƯưƱƲƳƴƵƶƷƸƹƺƻƼƽƾƿǀ
      Ƈ
      ǁǂǃǄǅǆǇǈǉǊǋǌǍǎǏǐǑǒǓǔǕǖ
      ǗǘǙǚǛǜǝǞǟǠǡǢǣǤǥǦǧǨǩǪǫǬǭǮǯǰǱǲǳǴǵǶǷǸǹǺǻǼǽǾǿȀȁȂȃȄȅȆȇȈȉȊȋȌȍȎȏȐȑ
      ȒȓȔȕȖȗȘșȚțȜȝȞȟȠȡȢȣȤȥȦȧȨȩȪȫȬ
      ȒȓȔȕȖȗȘșȚțȜȝȞȟȠȡȢȣȤȥȦȧȨȩȪȫȬǲǳǴǵǶǷǸǹǺǻǼǽǾǿȀȁȂȃȄȅȆȇȈȉȊȋȌȍȎȏȐȑ
      ȭȮȯȰȱȲȳȴȵȶȷȸȹȺȻȼȽȾȿɀɁɂɃɄɅɆɇɈɉɊɋɌɍɎɏɐɑɒɓɔɕɖɗɘəɚɛɜɝɞɟɠɡɢɣɤɥɦɧɨɩɪɫɬɭɮɯɰ
      ɱɲɳɴɵɶɷɸɹɺɻɼɽɾɿʀʁʂʃʄ
      ɱɲɳɴɵɶɷɸɹɺɻɼɽɾɿʀʁʂʃ
      ʅʆʇʈʉʊʋʌʍʎʏʐʑʒʓʔʕʖʗʘʙʚʛʜʝʞʟʠʡʢʣʤʥʦʧʨʩʪʫʬʭʮʯʰ
      ʱʲʳʴʵʶʷʸʹʺʻʼʽʾʿˀˁ˂˃˄˅ˆˇˈˉˊˋˌˍˎˏːˑ˒˓˔˕˖˗˘˙˚˛˜˝˞˟ˠˡˢˣˤ˥˦
      ˧˨˩˪˫ˬ˭ˮ˯˰˱˲˳˴˵˶˷˸˹˺˻˼˽˾
      """.lines(),
      scaleMultiplier: 1/10
  )
  static let slowerPrenormal = Workload(
    name: "SlowerPrenormal",
    payload: """
      Swiftに大幅な改良が施され、
      安定していてしかも
      直感的に使うことができる
      向けプログラミング言語になりました。
      이번 업데이트에서는 강력하면서도
      \u{201c}Hello\u{2010}world\u{2026}\u{201d}
      平台的编程语言
      功能强大且直观易用
      而本次更新对其进行了全面优化
      в чащах юга жил-был цитрус
      \u{300c}\u{300e}今日は\u{3001}世界\u{3002}\u{300f}\u{300d}
      но фальшивый экземпляр
      """.lines(),
      scaleMultiplier: 1/10
  )
  // static let slowestPrenormal = """
  //   """.lines()
  static let nonBMPSlowestPrenormal = Workload(
    name: "NonBMPSlowestPrenormal",
    payload: """
      𓀀𓀤𓁓𓁲𓃔𓃗
      𓀀𓀁𓀂𓀃𓀄𓀇𓀈𓀉𓀊𓀋𓀌𓀍𓀎𓀏𓀓𓀔𓀕𓀖𓀗𓀘𓀙𓀚𓀛𓀜𓀞𓀟𓀠𓀡𓀢𓀣
      𓀤𓀥𓀦𓀧𓀨𓀩𓀪𓀫𓀬𓀭
      𓁡𓁢𓁣𓁤𓁥𓁦𓁧𓁨𓁩𓁫𓁬𓁭𓁮𓁯𓁰𓁱𓁲𓁳𓁴𓁵𓁶𓁷𓁸
      𓁹𓁺𓁓𓁔𓁕𓁻𓁼𓁽𓁾𓁿
      𓀀𓀁𓀂𓀃𓀄𓃒𓃓𓃔𓃕𓃻𓃼𓃽𓃾𓃿𓄀𓄁𓄂𓄃𓄄𓄅𓄆𓄇𓄈𓄉𓄊𓄋𓄌𓄍𓄎
      𓂿𓃀𓃁𓃂𓃃𓃄𓃅
      𓃘𓃙𓃚𓃛𓃠𓃡𓃢𓃣𓃦𓃧𓃨𓃩𓃬𓃭𓃮𓃯𓃰𓃲𓃳𓃴𓃵𓃶𓃷𓃸
      𓃘𓃙𓃚𓃛𓃠𓃡𓃢𓃣𓃦𓃧𓃨𓃩𓃬𓃭𓃮𓃯𓃰𓃲𓃳𓃴𓃵𓃶𓃷
      𓀀𓀁𓀂𓀃𓀄𓆇𓆈𓆉𓆊𓆋𓆌𓆍𓆎𓆏𓆐𓆑𓆒𓆓𓆔𓆗𓆘𓆙𓆚𓆛𓆝𓆞𓆟𓆠𓆡𓆢𓆣𓆤
      𓆥𓆦𓆧𓆨𓆩𓆪𓆫𓆬𓆭𓆮𓆯𓆰𓆱𓆲𓆳𓆴𓆵𓆶𓆷𓆸𓆹𓆺𓆻
      """.lines(),
      scaleMultiplier: 1/10
  )
  static let emoji = Workload(
    name: "Emoji",
    payload: """
      👍👩‍👩‍👧‍👧👨‍👨‍👦‍👦🇺🇸🇨🇦🇲🇽👍🏻👍🏼👍🏽👍🏾👍🏿
      👍👩‍👩‍👧‍👧👨‍👨‍👦‍👦🇺🇸🇨🇦🇲🇽👍🏿👍🏻👍🏼👍🏽👍🏾
      😀🧀😀😃😄😁🤣😂😅😆
      😺🎃🤖👾😸😹😻😼😾😿🙀😽🙌🙏🤝👍✌🏽
      ☺️😊😇🙂😍😌😉🙃😘😗😙😚😛😝😜
      😋🤑🤗🤓😎😒😏🤠🤡😞😔😟😕😖😣☹️🙁😫😩😤😠😑😐😶😡😯
      😦😧😮😱😳😵😲😨😰😢😥
      😪😓😭🤤😴🙄🤔🤥🤧🤢🤐😬😷🤒🤕😈💩👺👹👿👻💀☠️👽
      """.lines(),
      scaleMultiplier: 1/4
  )

  static let abnormal = Workload(
    name: "Abnormal",
    payload: """
    ae\u{301}ae\u{301}ae\u{302}ae\u{303}ae\u{304}ae\u{305}ae\u{306}ae\u{307}
    ae\u{301}ae\u{301}ae\u{301}ae\u{301}ae\u{301}ae\u{301}ae\u{301}ae\u{300}
    \u{f900}\u{f901}\u{f902}\u{f903}\u{f904}\u{f905}\u{f906}\u{f907}\u{f908}\u{f909}\u{f90a}
    \u{f90b}\u{f90c}\u{f90d}\u{f90e}\u{f90f}\u{f910}\u{f911}\u{f912}\u{f913}\u{f914}\u{f915}\u{f916}\u{f917}\u{f918}\u{f919}
    \u{f900}\u{f91a}\u{f91b}\u{f91c}\u{f91d}\u{f91e}\u{f91f}\u{f920}\u{f921}\u{f922}
    """.lines(),
    scaleMultiplier: 1/20
  )
  // static let pathological = """
  //   """.lines()
  static let zalgo = Workload(
    name: "Zalgo",
    payload: """
    ṭ̴̵̶̷̸̢̧̨̡̛̤̥̦̩̪̫̬̭̮̯̰̖̗̘̙̜̝̞̟̠̱̲̳̹̺̻̼͇͈͉͍͎̀́̂̃̄̅̆̇̈̉ͣͤ̊̋̌̍̎̏̐̑̒̓̔̽̾̿̀́͂̓̈́͆͊͋͌̕̚͜͟͢͝͞͠͡ͅ͏͓͔͕͖͙͚͐͑͒͗͛ͣͤͥͦͧͨͩͪͫͬͭͮ͘͜͟͢͝͞͠͡
    h̀́̂̃
    è͇͈͉͍͎́̂̃̄̅̆̇̈̉͊͋͌͏̡̢̧̨̛͓͔͕͖͙͚̖̗̘̙̜̝̞̟̠̣̤̥̦̩̪̫̬̭͇͈͉͍͎͐͑͒͗͛̊̋̌̍̎̏̐̑̒̓̔̀́͂̓̈́͆͊͋͌͘̕̚͜͟͝͞͠ͅ͏͓͔͕͖͐͑͒
    q̴̵̶̷̸̡̢̧̨̛̖̗̘̙̜̝̞̟̠̣̤̥̦̩̪̫̬̭̮̯̰̱̲̳̹̺̻̼͇̀́̂̃̄̅̆̇̈̉̊̋̌̍̎̏̐̑̒̓̔̽̾̿̀́͂̓̈́͆̕̚ͅ
    ư̴̵̶̷̸̗̘̙̜̹̺̻̼͇͈͉͍͎̽̾̿̀́͂̓̈́͆͊͋͌̚ͅ͏͓͔͕͖͙͚͐͑͒͗͛ͣͤͥͦͧͨͩͪͫͬͭͮ͘͜͟͢͝͞͠͡
    ì̡̢̧̨̝̞̟̠̣̤̥̦̩̪̫̬̭̮̯̰̹̺̻̼͇͈͉͍͎́̂̃̄̉̊̋̌̍̎̏̐̑̒̓̽̾̿̀́͂̓̈́͆͊͋͌ͅ͏͓͔͕͖͙͐͑͒͗ͬͭͮ͘
    c̴̵̶̷̸̡̢̧̨̛̖̗̘̙̜̝̞̟̠̣̤̥̦̩̪̫̬̭̮̯̰̱̲̳̹̺̻̼̀́̂̃̄̔̽̾̿̀́͂̓̈́͆ͣͤͥͦͧͨͩͪͫͬͭͮ̕̚͢͡ͅ
    k̴̵̶̷̸̡̢̧̨̛̖̗̘̙̜̝̞̟̠̣̤̥̦̩̪̫̬̭̮̯̰̱̲̳̹̺̻̼͇͈͉͍͎̀́̂̃̄̅̆̇̈̉̊̋̌̍̎̏̐̑̒̓̔̽̾̿̀́͂̓̈́͆͊͋͌̕̚ͅ͏͓͔͕͖͙͚͐͑͒͗͛ͣͤͥͦͧͨͩͪͫͬͭͮ͘͜͟͢͝͞͠͡
    b̴̵̶̷̸̡̢̛̗̘̙̜̝̞̟̠̹̺̻̼͇͈͉͍͎̽̾̿̀́͂̓̈́͆͊͋͌̚ͅ͏͓͔͕͖͙͚͐͑͒͗͛ͣͤͥͦͧͨͩͪͫͬͭͮ͘͜͟͢͝͞͠͡
    ŗ̴̵̶̷̸̨̛̩̪̫̯̰̱̲̳̹̺̻̼̬̭̮͇̗̘̙̜̝̞̟̤̥̦͉͍͎̽̾̿̀́͂̓̈́͆͊͋͌̚ͅ͏̡̢͓͔͕͖͙͚̠̣͐͑͒͗͛ͣͤͥͦͧͨͩͪͫͬͭͮ͘͜͟͢͝͞͠͡
    o
    w̗̘͇͈͉͍͎̓̈́͆͊͋͌ͅ͏̛͓͔͕͖͙͚̙̜̹̺̻̼͐͑͒͗͛ͣͤͥͦ̽̾̿̀́͂ͧͨͩͪͫͬͭͮ͘̚͜͟͢͝͞͠͡
    n͇͈͉͍͎͊͋͌ͧͨͩͪͫͬͭͮ͏̛͓͔͕͖͙͚̗̘̙̜̹̺̻̼͐͑͒͗͛ͣͤͥͦ̽̾̿̀́͂̓̈́͆ͧͨͩͪͫͬͭͮ͘̚͜͟͢͝͞͠͡ͅ
    f̛̗̘̙̜̹̺̻̼͇͈͉͍͎̽̾̿̀́͂̓̈́͆͊͋͌̚ͅ͏͓͔͕͖͙͚͐͑͒͗͛ͣͤͥͦ͘͜͟͢͝͞͠͡
    ơ̗̘̙̜̹̺̻̼͇͈͉͍͎̽̾̿̀́͂̓̈́͆͊͋͌̚ͅ͏͓͔͕͖͙͚͐͑͒͗͛ͥͦͧͨͩͪͫͬͭͮ͘
    xͣͤͥͦͧͨͩͪͫͬͭͮ
    """.lines(),
    scaleMultiplier: 1/100
  )

  static let longSharedPrefix = Workload(
    name: "LongSharedPrefix",
    payload: """
    http://www.dogbook.com/dog/239495828/friends/mutual/2939493815
    http://www.dogbook.com/dog/239495828/friends/mutual/3910583739
    http://www.dogbook.com/dog/239495828/friends/mutual/3910583739/shared
    http://www.dogbook.com/dog/239495828/friends/mutual/3910583739/shared
    Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
    Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
    Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.🤔
    Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
    🤔Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.🤔
    """.lines()
  )

}

// Local Variables:
// eval: (read-only-mode 1)
// End:
