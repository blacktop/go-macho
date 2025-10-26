//
//  CwlDemangle.swift
//  CwlDemangle
//
//  Created by Matt Gallagher on 2017/11/17.
//  Copyright © 2017 Matt Gallagher. All rights reserved.
//

import Foundation

// MARK: Public interface

/// This is likely to be the primary entry point to this file. Pass a string containing a Swift mangled symbol or type, get a parsed SwiftSymbol structure which can then be directly examined or printed.
///
/// - Parameters:
///   - mangled: the string to be parsed ("isType` is false, the string should start with a Swift Symbol prefix, _T, _$S or $S).
///   - isType: if true, no prefix is parsed and, on completion, the first item on the parse stack is returned.
/// - Returns: the successfully parsed result
/// - Throws: a SwiftSymbolParseError error that contains parse position when the error occurred.
public func parseMangledSwiftSymbol(_ mangled: String, isType: Bool = false) throws -> SwiftSymbol {
	return try parseMangledSwiftSymbol(mangled.unicodeScalars, isType: isType)
}

/// Pass a collection of `UnicodeScalars` containing a Swift mangled symbol or type, get a parsed SwiftSymbol structure which can then be directly examined or printed.
///
/// - Parameters:
///   - mangled: the collection of `UnicodeScalars` to be parsed ("isType` is false, the string should start with a Swift Symbol prefix, _T, _$S or $S).
///   - isType: if true, no prefix is parsed and, on completion, the first item on the parse stack is returned.
/// - Returns: the successfully parsed result
/// - Throws: a SwiftSymbolParseError error that contains parse position when the error occurred.
public func parseMangledSwiftSymbol<C: Collection>(_ mangled: C, isType: Bool = false, symbolicReferenceResolver: ((Int32, Int) throws -> SwiftSymbol)? = nil) throws -> SwiftSymbol where C.Iterator.Element == UnicodeScalar {
	var demangler = Demangler(scalars: mangled)
	demangler.symbolicReferenceResolver = symbolicReferenceResolver
	if isType {
		return try demangler.demangleType()
	} else if getManglingPrefixLength(mangled) != 0 {
		return try demangler.demangleSymbol()
	} else {
		return try demangler.demangleSwift3TopLevelSymbol()
	}
}

extension SwiftSymbol: CustomStringConvertible {
	/// Overridden method to allow simple printing with default options
	public var description: String {
		var printer = SymbolPrinter()
		_ = printer.printName(self)
		return printer.target
	}
	
	/// Prints `SwiftSymbol`s to a String with the full set of printing options.
	///
	/// - Parameter options: an option set containing the different `DemangleOptions` from the Swift project.
	/// - Returns: `self` printed to a string according to the specified options.
	public func print(using options: SymbolPrintOptions = .default) -> String {
		var printer = SymbolPrinter(options: options)
		_ = printer.printName(self)
		return printer.target
	}
}

// MARK: Demangle.h

/// These options mimic those used in the Swift project. Check that project for details.
public struct SymbolPrintOptions: OptionSet {
	public let rawValue: Int
	
	public static let synthesizeSugarOnTypes = SymbolPrintOptions(rawValue: 1 << 0)
	public static let displayDebuggerGeneratedModule = SymbolPrintOptions(rawValue: 1 << 1)
	public static let qualifyEntities = SymbolPrintOptions(rawValue: 1 << 2)
	public static let displayExtensionContexts = SymbolPrintOptions(rawValue: 1 << 3)
	public static let displayUnmangledSuffix = SymbolPrintOptions(rawValue: 1 << 4)
	public static let displayModuleNames = SymbolPrintOptions(rawValue: 1 << 5)
	public static let displayGenericSpecializations = SymbolPrintOptions(rawValue: 1 << 6)
	public static let displayProtocolConformances = SymbolPrintOptions(rawValue: 1 << 7)
	public static let displayWhereClauses = SymbolPrintOptions(rawValue: 1 << 8)
	public static let displayEntityTypes = SymbolPrintOptions(rawValue: 1 << 9)
	public static let shortenPartialApply = SymbolPrintOptions(rawValue: 1 << 10)
	public static let shortenThunk = SymbolPrintOptions(rawValue: 1 << 11)
	public static let shortenValueWitness = SymbolPrintOptions(rawValue: 1 << 12)
	public static let shortenArchetype = SymbolPrintOptions(rawValue: 1 << 13)
	public static let showPrivateDiscriminators = SymbolPrintOptions(rawValue: 1 << 14)
	public static let showFunctionArgumentTypes = SymbolPrintOptions(rawValue: 1 << 15)
	public static let showAsyncResumePartial = SymbolPrintOptions(rawValue: 1 << 16)
	public static let displayStdlibModule = SymbolPrintOptions(rawValue: 1 << 17)
	public static let displayObjCModule = SymbolPrintOptions(rawValue: 1 << 18)
	public static let printForTypeName = SymbolPrintOptions(rawValue: 1 << 19)
	public static let showClosureSignature = SymbolPrintOptions(rawValue: 1 << 20)
	
	public init(rawValue: Int) {
		self.rawValue = rawValue
	}
	
	public static let `default`: SymbolPrintOptions = [.displayDebuggerGeneratedModule, .qualifyEntities, .displayExtensionContexts, .displayUnmangledSuffix, .displayModuleNames, .displayGenericSpecializations, .displayProtocolConformances, .displayWhereClauses, .displayEntityTypes, .showPrivateDiscriminators, .showFunctionArgumentTypes, .showAsyncResumePartial, .displayStdlibModule, .displayObjCModule, .showClosureSignature]
	public static let simplified: SymbolPrintOptions = [.synthesizeSugarOnTypes, .qualifyEntities, .shortenPartialApply, .shortenThunk, .shortenValueWitness, .shortenArchetype]
}

enum FunctionSigSpecializationParamKind: UInt64 {
	case constantPropFunction = 0
	case constantPropGlobal = 1
	case constantPropInteger = 2
	case constantPropFloat = 3
	case constantPropString = 4
	case closureProp = 5
	case boxToValue = 6
	case boxToStack = 7
	case inOutToOut = 8
	case constantPropKeyPath = 9
	
	case dead = 64
	case ownedToGuaranteed = 128
	case sroa = 256
	case guaranteedToOwned = 512
	case existentialToGeneric = 1024
}

enum SpecializationPass {
	case allocBoxToStack
	case closureSpecializer
	case capturePromotion
	case capturePropagation
	case functionSignatureOpts
	case genericSpecializer
}

enum Differentiability: UnicodeScalar {
	case normal = "d"
	case linear = "l"
	case forward = "f"
	case reverse = "r"
	
	init?(_ uint64: UInt64) {
		guard let uint32 = UInt32(exactly: uint64), let scalar = UnicodeScalar(uint32), let value = Differentiability(rawValue: scalar) else { return nil }
		self = value
	}
}

enum AutoDiffFunctionKind: UnicodeScalar {
	case forward = "f"
	case reverse = "r"
	case differential = "d"
	case pullback = "p"
	
	init?(_ uint64: UInt64) {
		guard let uint32 = UInt32(exactly: uint64), let scalar = UnicodeScalar(uint32), let value = AutoDiffFunctionKind(rawValue: scalar) else { return nil }
		self = value
	}
}

enum Directness: UInt64, CustomStringConvertible {
	case direct = 0
	case indirect = 1
	
	var description: String {
		switch self {
		case .direct: return "direct"
		case .indirect: return "indirect"
		}
	}
}

enum DemangleFunctionEntityArgs {
	case none, typeAndMaybePrivateName, typeAndIndex, index
}

enum DemangleGenericRequirementTypeKind {
	case generic, assoc, compoundAssoc, substitution
}

enum DemangleGenericRequirementConstraintKind {
	case `protocol`
	case baseClass
	case sameType
	case sameShape
	case layout
	case packMarker
	case inverse
	case valueMarker
}

enum ValueWitnessKind: UInt64, CustomStringConvertible {
	case allocateBuffer = 0
	case assignWithCopy = 1
	case assignWithTake = 2
	case deallocateBuffer = 3
	case destroy = 4
	case destroyArray = 5
	case destroyBuffer = 6
	case initializeBufferWithCopyOfBuffer = 7
	case initializeBufferWithCopy = 8
	case initializeWithCopy = 9
	case initializeBufferWithTake = 10
	case initializeWithTake = 11
	case projectBuffer = 12
	case initializeBufferWithTakeOfBuffer = 13
	case initializeArrayWithCopy = 14
	case initializeArrayWithTakeFrontToBack = 15
	case initializeArrayWithTakeBackToFront = 16
	case storeExtraInhabitant = 17
	case getExtraInhabitantIndex = 18
	case getEnumTag = 19
	case destructiveProjectEnumData = 20
	case destructiveInjectEnumTag = 21
	case getEnumTagSinglePayload = 22
	case storeEnumTagSinglePayload = 23
	
	init?(code: String) {
		switch code {
		case "al": self = .allocateBuffer
		case "ca": self = .assignWithCopy
		case "ta": self = .assignWithTake
		case "de": self = .deallocateBuffer
		case "xx": self = .destroy
		case "XX": self = .destroyBuffer
		case "Xx": self = .destroyArray
		case "CP": self = .initializeBufferWithCopyOfBuffer
		case "Cp": self = .initializeBufferWithCopy
		case "cp": self = .initializeWithCopy
		case "Tk": self = .initializeBufferWithTake
		case "tk": self = .initializeWithTake
		case "pr": self = .projectBuffer
		case "TK": self = .initializeBufferWithTakeOfBuffer
		case "Cc": self = .initializeArrayWithCopy
		case "Tt": self = .initializeArrayWithTakeFrontToBack
		case "tT": self = .initializeArrayWithTakeBackToFront
		case "xs": self = .storeExtraInhabitant
		case "xg": self = .getExtraInhabitantIndex
		case "ug": self = .getEnumTag
		case "up": self = .destructiveProjectEnumData
		case "ui": self = .destructiveInjectEnumTag
		case "et": self = .getEnumTagSinglePayload
		case "st": self = .storeEnumTagSinglePayload
		default: return nil
		}
	}
	
	var description: String {
		switch self {
		case .allocateBuffer: return "allocateBuffer"
		case .assignWithCopy: return "assignWithCopy"
		case .assignWithTake: return "assignWithTake"
		case .deallocateBuffer: return "deallocateBuffer"
		case .destroy: return "destroy"
		case .destroyBuffer: return "destroyBuffer"
		case .initializeBufferWithCopyOfBuffer: return "initializeBufferWithCopyOfBuffer"
		case .initializeBufferWithCopy: return "initializeBufferWithCopy"
		case .initializeWithCopy: return "initializeWithCopy"
		case .initializeBufferWithTake: return "initializeBufferWithTake"
		case .initializeWithTake: return "initializeWithTake"
		case .projectBuffer: return "projectBuffer"
		case .initializeBufferWithTakeOfBuffer: return "initializeBufferWithTakeOfBuffer"
		case .destroyArray: return "destroyArray"
		case .initializeArrayWithCopy: return "initializeArrayWithCopy"
		case .initializeArrayWithTakeFrontToBack: return "initializeArrayWithTakeFrontToBack"
		case .initializeArrayWithTakeBackToFront: return "initializeArrayWithTakeBackToFront"
		case .storeExtraInhabitant: return "storeExtraInhabitant"
		case .getExtraInhabitantIndex: return "getExtraInhabitantIndex"
		case .getEnumTag: return "getEnumTag"
		case .destructiveProjectEnumData: return "destructiveProjectEnumData"
		case .destructiveInjectEnumTag: return "destructiveInjectEnumTag"
		case .getEnumTagSinglePayload: return "getEnumTagSinglePayload"
		case .storeEnumTagSinglePayload: return "storeEnumTagSinglePayload"
		}
	}
}

public struct SwiftSymbol {
	public let kind: Kind
	public var children: [SwiftSymbol]
	public let contents: Contents
	
	public enum Contents {
		case none
		case index(UInt64)
		case name(String)
	}
	
	public init(kind: Kind, children: [SwiftSymbol] = [], contents: Contents = .none) {
		self.kind = kind
		self.children = children
		self.contents = contents
	}
	
	fileprivate init(kind: Kind, child: SwiftSymbol) {
		self.init(kind: kind, children: [child], contents: .none)
	}
	
	fileprivate init(typeWithChildKind: Kind, childChild: SwiftSymbol) {
		self.init(kind: .type, children: [SwiftSymbol(kind: typeWithChildKind, children: [childChild])], contents: .none)
	}
	
	fileprivate init(typeWithChildKind: Kind, childChildren: [SwiftSymbol]) {
		self.init(kind: .type, children: [SwiftSymbol(kind: typeWithChildKind, children: childChildren)], contents: .none)
	}
	
	fileprivate init(swiftStdlibTypeKind: Kind, name: String) {
		self.init(kind: .type, children: [SwiftSymbol(kind: swiftStdlibTypeKind, children: [
			SwiftSymbol(kind: .module, contents: .name(stdlibName)),
			SwiftSymbol(kind: .identifier, contents: .name(name))
		])], contents: .none)
	}
	
	fileprivate init(swiftBuiltinType: Kind, name: String) {
		self.init(kind: .type, children: [SwiftSymbol(kind: swiftBuiltinType, contents: .name(name))])
	}
	
	fileprivate var text: String? {
		switch contents {
		case .name(let s): return s
		default: return nil
		}
	}
	
	fileprivate var index: UInt64? {
		switch contents {
		case .index(let i): return i
		default: return nil
		}
	}
	
	fileprivate var isProtocol: Bool {
		switch kind {
		case .type: return children.first?.isProtocol ?? false
		case .protocol, .protocolSymbolicReference, .objectiveCProtocolSymbolicReference: return true
		default: return false
		}
	}
	
	
	fileprivate func changeChild(_ newChild: SwiftSymbol?, atIndex: Int) -> SwiftSymbol {
		guard children.indices.contains(atIndex) else { return self }
		
		var modifiedChildren = children
		if let nc = newChild {
			modifiedChildren[atIndex] = nc
		} else {
			modifiedChildren.remove(at: atIndex)
		}
		return SwiftSymbol(kind: kind, children: modifiedChildren, contents: contents)
	}
	
	fileprivate func changeKind(_ newKind: Kind, additionalChildren: [SwiftSymbol] = []) -> SwiftSymbol {
		if case .name(let text) = contents {
			return SwiftSymbol(kind: newKind, children: children + additionalChildren, contents: .name(text))
		} else if case .index(let i) = contents {
			return SwiftSymbol(kind: newKind, children: children + additionalChildren, contents: .index(i))
		} else {
			return SwiftSymbol(kind: newKind, children: children + additionalChildren, contents: .none)
		}
	}
}

// MARK: DemangleNodes.def

extension SwiftSymbol {
	public enum Kind {
		case allocator
		case accessibleFunctionRecord
		case accessorFunctionReference
		case accessorAttachedMacroExpansion
		case anonymousContext
		case anonymousDescriptor
		case anyProtocolConformanceList
		case argumentTuple
		case associatedConformanceDescriptor
		case associatedType
		case associatedTypeDescriptor
		case associatedTypeGenericParamRef
		case associatedTypeMetadataAccessor
		case associatedTypeRef
		case associatedTypeWitnessTableAccessor
		case assocTypePath
		case asyncAnnotation
		case asyncAwaitResumePartialFunction
		case asyncFunctionPointer
		case asyncRemoved
		case asyncSuspendResumePartialFunction
		case autoClosureType
		case autoDiffDerivativeVTableThunk
		case autoDiffFunction
		case autoDiffFunctionKind
		case autoDiffSelfReorderingReabstractionThunk
		case autoDiffSubsetParametersThunk
		case backDeploymentThunk
		case backDeploymentFallback
		case baseConformanceDescriptor
		case baseWitnessTableAccessor
		case bodyAttachedMacroExpansion
		case boundGenericClass
		case boundGenericEnum
		case boundGenericFunction
		case boundGenericOtherNominalType
		case boundGenericProtocol
		case boundGenericStructure
		case boundGenericTypeAlias
		case builtinTypeName
		case builtinTupleType
		case builtinFixedArray
		case canonicalPrespecializedGenericTypeCachingOnceToken
		case canonicalSpecializedGenericMetaclass
		case canonicalSpecializedGenericTypeMetadataAccessFunction
		case cFunctionPointer
		case clangType
		case `class`
		case classMetadataBaseOffset
		case compileTimeConst
		case concreteProtocolConformance
		case concurrentFunctionType
		case conformanceAttachedMacroExpansion
		case constrainedExistential
		case constrainedExistentialRequirementList
		case constrainedExistentialSelf
		case constructor
		case coroutineContinuationPrototype
		case curryThunk
		case deallocator
		case declContext
		case defaultArgumentInitializer
		case defaultAssociatedConformanceAccessor
		case defaultAssociatedTypeMetadataAccessor
		case dependentAssociatedConformance
		case dependentAssociatedTypeRef
		case dependentGenericConformanceRequirement
		case dependentGenericInverseConformanceRequirement
		case dependentGenericLayoutRequirement
		case dependentGenericParamCount
		case dependentGenericParamPackMarker
		case dependentGenericParamValueMarker
		case dependentGenericParamType
		case dependentGenericSameShapeRequirement
		case dependentGenericSameTypeRequirement
		case dependentGenericSignature
		case dependentGenericType
		case dependentMemberType
		case dependentProtocolConformanceAssociated
		case dependentProtocolConformanceInherited
		case dependentProtocolConformanceRoot
		case dependentPseudogenericSignature
		case destructor
		case didSet
		case differentiabilityWitness
		case differentiableFunctionType
		case directMethodReferenceAttribute
		case directness
		case dispatchThunk
		case distributedAccessor
		case distributedThunk
		case droppedArgument
		case dynamicallyReplaceableFunctionImpl
		case dynamicallyReplaceableFunctionKey
		case dynamicallyReplaceableFunctionVar
		case dynamicAttribute
		case dynamicSelf
		case emptyList
		case `enum`
		case enumCase
		case errorType
		case escapingAutoClosureType
		case escapingObjCBlock
		case existentialMetatype
		case `extension`
		case explicitClosure
		case extendedExistentialTypeShape
		case extensionAttachedMacroExpansion
		case extensionDescriptor
		case fieldOffset
		case firstElementMarker
		case freestandingMacroExpansion
		case fullObjCResilientClassStub
		case fullTypeMetadata
		case function
		case functionSignatureSpecialization
		case functionSignatureSpecializationParam
		case functionSignatureSpecializationReturn
		case functionSignatureSpecializationParamKind
		case functionSignatureSpecializationParamPayload
		case functionType
		case genericPartialSpecialization
		case genericPartialSpecializationNotReAbstracted
		case genericProtocolWitnessTable
		case genericProtocolWitnessTableInstantiationFunction
		case genericSpecialization
		case genericSpecializationInResilienceDomain
		case genericSpecializationPrespecialized
		case genericSpecializationNotReAbstracted
		case genericSpecializationParam
		case genericTypeMetadataPattern
		case genericTypeParamDecl
		case getter
		case global
		case globalActorFunctionType
		case globalGetter
		case globalVariableOnceDeclList
		case globalVariableOnceToken
		case globalVariableOnceFunction
		case hasSymbolQuery
		case identifier
		case implConvention
		case implDifferentiabilityKind
		case implErrorResult
		case implEscaping
		case implErasedIsolation
		case implSendingResult
		case implParameterResultDifferentiability
		case implParameterSending
		case implFunctionAttribute
		case implFunctionConvention
		case implFunctionConventionName
		case implFunctionType
		case implCoroutineKind
		case implicitClosure
		case implInvocationSubstitutions
		case implParameter
		case implPatternSubstitutions
		case implResult
		case implYield
		case index
		case indexSubset
		case infixOperator
		case initAccessor
		case initializer
		case inlinedGenericFunction
		case inOut
		case integer
		case isolated
		case isolatedDeallocator
		case isolatedAnyFunctionType
		case isSerialized
		case iVarDestroyer
		case iVarInitializer
		case keyPathEqualsThunkHelper
		case keyPathGetterThunkHelper
		case keyPathHashThunkHelper
		case keyPathSetterThunkHelper
		case labelList
		case lazyProtocolWitnessTableAccessor
		case lazyProtocolWitnessTableCacheVariable
		case localDeclName
		case macro
		case macroExpansionLoc
		case macroExpansionUniqueName
		case materializeForSet
		case memberAttachedMacroExpansion
		case memberAttributeAttachedMacroExpansion
		case mergedFunction
		case metaclass
		case metadataInstantiationCache
		case metatype
		case metatypeRepresentation
		case methodDescriptor
		case methodLookupFunction
		case modifyAccessor
		case modify2Accessor
		case module
		case moduleDescriptor
		case nativeOwningAddressor
		case nativeOwningMutableAddressor
		case nativePinningAddressor
		case nativePinningMutableAddressor
		case negativeInteger
		case noDerivative
		case noEscapeFunctionType
		case nominalTypeDescriptor
		case nominalTypeDescriptorRecord
		case noncanonicalSpecializedGenericTypeMetadata
		case noncanonicalSpecializedGenericTypeMetadataCache
		case nonObjCAttribute
		case nonUniqueExtendedExistentialTypeShapeSymbolicReference
		case number
		case objCAttribute
		case objCAsyncCompletionHandlerImpl
		case objCBlock
		case objCMetadataUpdateFunction
		case objCResilientClassStub
		case objectiveCProtocolSymbolicReference
		case opaqueReturnType
		case opaqueReturnTypeIndex
		case opaqueReturnTypeOf
		case opaqueReturnTypeParent
		case opaqueType
		case opaqueTypeDescriptor
		case opaqueTypeDescriptorAccessor
		case opaqueTypeDescriptorAccessorImpl
		case opaqueTypeDescriptorAccessorKey
		case opaqueTypeDescriptorAccessorVar
		case opaqueTypeDescriptorRecord
		case opaqueTypeDescriptorSymbolicReference
		case otherNominalType
		case outlinedAssignWithCopy
		case outlinedAssignWithCopyNoValueWitness
		case outlinedAssignWithTake
		case outlinedAssignWithTakeNoValueWitness
		case outlinedBridgedMethod
		case outlinedConsume
		case outlinedCopy
		case outlinedDestroy
		case outlinedDestroyNoValueWitness
		case outlinedEnumGetTag
		case outlinedEnumProjectDataForLoad
		case outlinedEnumTagStore
		case outlinedInitializeWithCopy
		case outlinedInitializeWithCopyNoValueWitness
		case outlinedInitializeWithTake
		case outlinedRelease
		case outlinedRetain
		case outlinedVariable
		case outlinedReadOnlyObject
		case owned
		case owningAddressor
		case owningMutableAddressor
		case pack
		case packElement
		case packElementLevel
		case packExpansion
		case packProtocolConformance
		case partialApplyForwarder
		case partialApplyObjCForwarder
		case peerAttachedMacroExpansion
		case postfixOperator
		case prefixOperator
		case predefinedObjCAsyncCompletionHandlerImpl
		case privateDeclName
		case propertyDescriptor
		case propertyWrapperBackingInitializer
		case propertyWrapperInitFromProjectedValue
		case `protocol`
		case protocolConformance
		case protocolConformanceDescriptorRecord
		case protocolConformanceRefInTypeModule
		case protocolConformanceRefInProtocolModule
		case protocolConformanceRefInOtherModule
		case protocolConformanceDescriptor
		case protocolDescriptor
		case protocolDescriptorRecord
		case protocolList
		case protocolListWithAnyObject
		case protocolListWithClass
		case protocolRequirementsBaseDescriptor
		case protocolSelfConformanceDescriptor
		case protocolSelfConformanceWitness
		case protocolSelfConformanceWitnessTable
		case protocolSymbolicReference
		case protocolWitness
		case protocolWitnessTable
		case protocolWitnessTableAccessor
		case protocolWitnessTablePattern
		case reabstractionThunk
		case reabstractionThunkHelper
		case reabstractionThunkHelperWithGlobalActor
		case reabstractionThunkHelperWithSelf
		case readAccessor
		case read2Accessor
		case reflectionMetadataAssocTypeDescriptor
		case reflectionMetadataBuiltinDescriptor
		case reflectionMetadataFieldDescriptor
		case reflectionMetadataSuperclassDescriptor
		case relatedEntityDeclName
		case resilientProtocolWitnessTable
		case retroactiveConformance
		case returnType
		case sending
		case sendingResultFunctionType
		case setter
		case shared
		case silBoxImmutableField
		case silBoxLayout
		case silBoxMutableField
		case silBoxType
		case silBoxTypeWithLayout
		case silPackDirect
		case silPackIndirect
		case silThunkIdentity
		case silThunkHopToMainActorIfNeeded
		case specializationPassID
		case `static`
		case structure
		case `subscript`
		case suffix
		case sugaredOptional
		case sugaredArray
		case sugaredDictionary
		case sugaredParen
		case symbolicExtendedExistentialType
		case typeSymbolicReference
		case thinFunctionType
		case throwsAnnotation
		case tuple
		case tupleElement
		case tupleElementName
		case type
		case typeAlias
		case typedThrowsAnnotation
		case typeList
		case typeMangling
		case typeMetadata
		case typeMetadataAccessFunction
		case typeMetadataCompletionFunction
		case typeMetadataDemanglingCache
		case typeMetadataInstantiationCache
		case typeMetadataInstantiationFunction
		case typeMetadataLazyCache
		case typeMetadataSingletonInitializationCache
		case uncurriedFunctionType
		case uniquable
		case uniqueExtendedExistentialTypeShapeSymbolicReference
		case unknownIndex
		case unmanaged
		case unowned
		case unsafeAddressor
		case unsafeMutableAddressor
		case valueWitness
		case valueWitnessTable
		case variable
		case variadicMarker
		case vTableAttribute // note: old mangling only
		case vTableThunk
		case weak
		case willSet
	}
}

// MARK: Demangler.h

fileprivate let stdlibName = "Swift"
fileprivate let objcModule = "__C"
fileprivate let cModule = "__C_Synthesized"
fileprivate let lldbExpressionsModuleNamePrefix = "__lldb_expr_"
fileprivate let maxRepeatCount = 2048
fileprivate let maxNumWords = 26

fileprivate struct Demangler<C> where C: Collection, C.Iterator.Element == UnicodeScalar {
	var scanner: ScalarScanner<C>
	var nameStack: [SwiftSymbol] = []
	var substitutions: [SwiftSymbol] = []
	var words: [String] = []
	var symbolicReferences: [Int32] = []
	var isOldFunctionTypeMangling: Bool = false
	var symbolicReferenceResolver: ((Int32, Int) throws -> SwiftSymbol)? = nil
	var flavor: ManglingFlavor = .default
	
	init(scalars: C) {
		scanner = ScalarScanner(scalars: scalars)
	}
}

// MARK: Demangler.cpp

fileprivate func getManglingPrefixLength<C: Collection>(_ scalars: C) -> Int where C.Iterator.Element == UnicodeScalar {
	var scanner = ScalarScanner(scalars: scalars)
	if scanner.conditional(string: "_T0") || scanner.conditional(string: "_$S") || scanner.conditional(string: "_$s") || scanner.conditional(string: "_$e") {
		return 3
	} else if scanner.conditional(string: "$S") || scanner.conditional(string: "$s") || scanner.conditional(string: "$e") {
		return 2
	} else if scanner.conditional(string: "@__swiftmacro_") {
		return 14
	}
	
	return 0
}

fileprivate extension SwiftSymbol.Kind {
	var isDeclName: Bool {
		switch self {
		case .identifier, .localDeclName, .privateDeclName, .relatedEntityDeclName: fallthrough
		case .prefixOperator, .postfixOperator, .infixOperator: fallthrough
		case .typeSymbolicReference, .protocolSymbolicReference, .objectiveCProtocolSymbolicReference: return true
		default: return false
		}
	}
	
	var isContext: Bool {
		switch self {
		case .allocator, .anonymousContext, .autoDiffFunction, .class, .constructor, .curryThunk, .deallocator, .defaultArgumentInitializer: fallthrough
		case .destructor, .didSet, .dispatchThunk, .enum, .explicitClosure, .extension, .function: fallthrough
		case .getter, .globalGetter, .iVarInitializer, .iVarDestroyer, .implicitClosure: fallthrough
		case .initializer, .initAccessor, .isolatedDeallocator, .materializeForSet, .modifyAccessor, .modify2Accessor: fallthrough
		case .module, .nativeOwningAddressor: fallthrough
		case .nativeOwningMutableAddressor, .nativePinningAddressor, .nativePinningMutableAddressor, .opaqueReturnTypeOf: fallthrough
		case .otherNominalType, .owningAddressor, .owningMutableAddressor, .propertyWrapperBackingInitializer: fallthrough
		case .propertyWrapperInitFromProjectedValue, .protocol, .protocolSymbolicReference, .readAccessor: fallthrough
		case .read2Accessor, .setter, .static: fallthrough
		case .structure, .subscript, .typeSymbolicReference, .typeAlias, .unsafeAddressor, .unsafeMutableAddressor: fallthrough
		case .variable, .willSet: return true
		default: return false
		}
	}
	
	var isAnyGeneric: Bool {
		switch self {
		case .structure, .class, .enum, .protocol, .protocolSymbolicReference, .otherNominalType, .typeAlias, .typeSymbolicReference, .objectiveCProtocolSymbolicReference: return true
		default: return false
		}
	}
	
	var isEntity: Bool {
		return self == .type || isContext
	}
	
	var isRequirement: Bool {
		switch self {
		case .dependentGenericParamPackMarker, .dependentGenericParamValueMarker, .dependentGenericSameTypeRequirement, .dependentGenericSameShapeRequirement: fallthrough
		case .dependentGenericLayoutRequirement, .dependentGenericConformanceRequirement, .dependentGenericInverseConformanceRequirement: return true
		default: return false
		}
	}
	
	var isFunctionAttr: Bool {
		switch self {
		case .functionSignatureSpecialization, .genericSpecialization, .genericSpecializationPrespecialized, .inlinedGenericFunction: fallthrough
		case .genericSpecializationNotReAbstracted, .genericPartialSpecialization: fallthrough
		case .genericPartialSpecializationNotReAbstracted, .genericSpecializationInResilienceDomain, .objCAttribute, .nonObjCAttribute: fallthrough
		case .dynamicAttribute, .directMethodReferenceAttribute, .vTableAttribute, .partialApplyForwarder: fallthrough
		case .partialApplyObjCForwarder, .outlinedVariable, .outlinedReadOnlyObject, .outlinedBridgedMethod, .mergedFunction: fallthrough
		case .distributedThunk, .distributedAccessor: fallthrough
		case .dynamicallyReplaceableFunctionImpl, .dynamicallyReplaceableFunctionKey, .dynamicallyReplaceableFunctionVar: fallthrough
		case .asyncFunctionPointer, .asyncAwaitResumePartialFunction, .asyncSuspendResumePartialFunction: fallthrough
		case .accessibleFunctionRecord, .backDeploymentThunk, .backDeploymentFallback: fallthrough
		case .hasSymbolQuery: return true
		default: return false
		}
	}
}

fileprivate extension Demangler {
	func require<T>(_ optional: Optional<T>) throws -> T {
		if let v = optional {
			return v
		} else {
			throw failure
		}
	}
	
	func require(_ value: Bool) throws {
		if !value {
			throw failure
		}
	}
	
	var failure: Error {
		return scanner.unexpectedError()
	}
	
	mutating func readManglingPrefix() throws {
		let prefixes = [
			"_T0", "$S", "_$S", "$s", "_$s", "$e", "_$e", "@__swiftmacro_"
		]
		for prefix in prefixes {
			if scanner.conditional(string: prefix) {
				return
			}
		}
		throw scanner.unexpectedError()
	}
	
	mutating func reset() {
		nameStack = []
		substitutions = []
		words = []
		scanner.reset()
	}
	
	mutating func popTopLevelInto(_ parent: inout SwiftSymbol) throws {
		while var funcAttr = pop(where: { $0.isFunctionAttr }) {
			switch funcAttr.kind {
			case .partialApplyForwarder, .partialApplyObjCForwarder:
				try popTopLevelInto(&funcAttr)
				parent.children.append(funcAttr)
				return
			default:
				parent.children.append(funcAttr)
			}
		}
		for name in nameStack {
			switch name.kind {
			case .type: parent.children.append(try require(name.children.first))
			default: parent.children.append(name)
			}
		}
	}
	
	mutating func demangleSymbol() throws -> SwiftSymbol {
		reset()
		
		if scanner.conditional(string: "_Tt") {
			return try demangleObjCTypeName()
		} else if scanner.conditional(string: "_T") {
			isOldFunctionTypeMangling = true
			try scanner.backtrack(count: 2)
		}
		
		try readManglingPrefix()
		try parseAndPushNames()
		
		let suffix = pop(kind: .suffix)
		var topLevel = SwiftSymbol(kind: .global)
		try popTopLevelInto(&topLevel)
		if let suffix {
			topLevel.children.append(suffix)
		}
		try require(topLevel.children.count != 0)
		return topLevel
	}
	
	mutating func demangleType() throws -> SwiftSymbol {
		reset()
		
		try parseAndPushNames()
		if let result = pop() {
			return result
		}
		
		return SwiftSymbol(kind: .suffix, children: [], contents: .name(String(String.UnicodeScalarView(scanner.scalars))))
	}
	
	mutating func parseAndPushNames() throws {
		while !scanner.isAtEnd {
			nameStack.append(try demangleOperator())
		}
	}
	
	mutating func demangleSymbolicReference() throws -> SwiftSymbol {
		throw SwiftSymbolParseError.unimplementedFeature
	}
	
	mutating func demangleTypeAnnotation() throws -> SwiftSymbol {
		switch try scanner.readScalar() {
		case "a": return SwiftSymbol(kind: .asyncAnnotation)
		case "A": return SwiftSymbol(kind: .isolatedAnyFunctionType)
		case "b": return SwiftSymbol(kind: .concurrentFunctionType)
		case "c": return SwiftSymbol(kind: .globalActorFunctionType, child: try require(popTypeAndGetChild()))
		case "i": return SwiftSymbol(typeWithChildKind: .isolated, childChild: try require(popTypeAndGetChild()))
		case "j": return try demangleDifferentiableFunctionType()
		case "k": return SwiftSymbol(typeWithChildKind: .noDerivative, childChild: try require(popTypeAndGetChild()))
		case "K": return SwiftSymbol(kind: .typedThrowsAnnotation, child: try require(popTypeAndGetChild()))
		case "t": return SwiftSymbol(typeWithChildKind: .compileTimeConst, childChild: try require(popTypeAndGetChild()))
		case "T": return SwiftSymbol(kind: .sendingResultFunctionType)
		case "u": return SwiftSymbol(typeWithChildKind: .sending, childChild: try require(popTypeAndGetChild()))
		default: throw failure
		}
	}
	
	mutating func demangleOperator() throws -> SwiftSymbol {
		switch try scanner.readScalar() {
		case "\u{1}", "\u{2}", "\u{3}", "\u{4}", "\u{5}", "\u{6}", "\u{7}", "\u{8}", "\u{9}", "\u{A}", "\u{B}", "\u{C}":
			try scanner.backtrack()
			return try demangleSymbolicReference()
		case "A": return try demangleMultiSubstitutions()
		case "B": return try demangleBuiltinType()
		case "C": return try demangleAnyGenericType(kind: .class)
		case "D": return SwiftSymbol(kind: .typeMangling, child: try require(pop(kind: .type)))
		case "E": return try demangleExtensionContext()
		case "F": return try demanglePlainFunction()
		case "G": return try demangleBoundGenericType()
		case "H":
			switch try scanner.readScalar() {
			case "A": return try demangleDependentProtocolConformanceAssociated()
			case "C": return try demangleConcreteProtocolConformance()
			case "D": return try demangleDependentProtocolConformanceRoot()
			case "I": return try demangleDependentProtocolConformanceInherited()
			case "P": return SwiftSymbol(kind: .protocolConformanceRefInTypeModule, child: try popProtocol())
			case "p": return SwiftSymbol(kind: .protocolConformanceRefInProtocolModule, child: try popProtocol())
			case "X": return SwiftSymbol(kind: .packProtocolConformance, child: try popAnyProtocolConformanceList())
			case "c": return SwiftSymbol(kind: .protocolConformanceDescriptorRecord, child: try popProtocolConformance())
			case "n": return SwiftSymbol(kind: .nominalTypeDescriptorRecord, child: try require(pop(kind: .type)))
			case "o": return SwiftSymbol(kind: .opaqueTypeDescriptorRecord, child: try require(pop()))
			case "r": return SwiftSymbol(kind: .protocolDescriptorRecord, child: try popProtocol())
			case "F": return SwiftSymbol(kind: .accessibleFunctionRecord)
			default:
				try scanner.backtrack(count: 2)
				return try demangleIdentifier()
			}
		case "I": return try demangleImplFunctionType()
		case "K": return SwiftSymbol(kind: .throwsAnnotation)
		case "L": return try demangleLocalIdentifier()
		case "M": return try demangleMetatype()
		case "N": return SwiftSymbol(kind: .typeMetadata, child: try require(pop(kind: .type)))
		case "O": return try demangleAnyGenericType(kind: .enum)
		case "P": return try demangleAnyGenericType(kind: .protocol)
		case "Q": return try demangleArchetype()
		case "R": return try demangleGenericRequirement()
		case "S": return try demangleStandardSubstitution()
		case "T": return try demangleThunkOrSpecialization()
		case "V": return try demangleAnyGenericType(kind: .structure)
		case "W": return try demangleWitness()
		case "X": return try demangleSpecialType()
		case "Y": return try demangleTypeAnnotation()
		case "Z": return SwiftSymbol(kind: .static, child: try require(pop(where: { $0.isEntity })))
		case "a": return try demangleAnyGenericType(kind: .typeAlias)
		case "c": return try require(popFunctionType(kind: .functionType))
		case "d": return SwiftSymbol(kind: .variadicMarker)
		case "f": return try demangleFunctionEntity()
		case "g": return try demangleRetroactiveConformance()
		case "h": return SwiftSymbol(typeWithChildKind: .shared, childChild: try require(popTypeAndGetChild()))
		case "i": return try demangleSubscript()
		case "l": return try demangleGenericSignature(hasParamCounts: false)
		case "m": return SwiftSymbol(typeWithChildKind: .metatype, childChild: try require(pop(kind: .type)))
		case "n": return SwiftSymbol(typeWithChildKind: .owned, childChild: try popTypeAndGetChild())
		case "o": return try demangleOperatorIdentifier();
		case "p": return try demangleProtocolListType();
		case "q": return SwiftSymbol(kind: .type, child: try demangleGenericParamIndex())
		case "r": return try demangleGenericSignature(hasParamCounts: true)
		case "s": return SwiftSymbol(kind: .module, contents: .name(stdlibName))
		case "t": return try popTuple()
		case "u": return try demangleGenericType()
		case "v": return try demangleVariable()
		case "w": return try demangleValueWitness()
		case "x": return SwiftSymbol(kind: .type, child: try getDependentGenericParamType(depth: 0, index: 0))
		case "y": return SwiftSymbol(kind: .emptyList)
		case "z": return SwiftSymbol(typeWithChildKind: .inOut, childChild: try require(popTypeAndGetChild()))
		case "_": return SwiftSymbol(kind: .firstElementMarker)
		case ".":
			try scanner.backtrack()
			return SwiftSymbol(kind: .suffix, contents: .name(scanner.remainder()))
		case "$": return try demangleIntegerType()
		default:
			try scanner.backtrack()
			return try demangleIdentifier()
		}
	}
	
	mutating func demangleNatural() throws -> UInt64? {
		return try scanner.conditionalInt()
	}
	
	mutating func demangleIndex() throws -> UInt64 {
		if scanner.conditional(scalar: "_") {
			return 0
		}
		let value = try require(demangleNatural())
		try scanner.match(scalar: "_")
		return value + 1
	}
	
	mutating func demangleIndexAsName() throws -> SwiftSymbol {
		return SwiftSymbol(kind: .number, contents: .index(try demangleIndex()))
	}
	
	mutating func demangleMultiSubstitutions() throws -> SwiftSymbol {
		var repeatCount: Int = -1
		while true {
			let c = try scanner.readScalar()
			if c == "\0" {
				throw scanner.unexpectedError()
			} else if c.isLower {
				let nd = try pushMultiSubstitutions(repeatCount: repeatCount, index: Int(c.value - UnicodeScalar("a").value))
				nameStack.append(nd)
				repeatCount = -1
				continue
			} else if c.isUpper {
				return try pushMultiSubstitutions(repeatCount: repeatCount, index: Int(c.value - UnicodeScalar("A").value))
			} else if c == "_" {
				let idx = Int(repeatCount + 27)
				return try require(substitutions.at(idx))
			} else {
				try scanner.backtrack()
				repeatCount = Int(try demangleNatural() ?? 0)
			}
		}
	}
	
	mutating func pushMultiSubstitutions(repeatCount: Int, index: Int) throws -> SwiftSymbol {
		try require(repeatCount <= maxRepeatCount)
		let nd = try require(substitutions.at(index))
		(0..<max(0, repeatCount - 1)).forEach { _ in nameStack.append(nd) }
		return nd
	}
	
	mutating func pop() -> SwiftSymbol? {
		return nameStack.popLast()
	}
	
	mutating func pop(kind: SwiftSymbol.Kind) -> SwiftSymbol? {
		return nameStack.last?.kind == kind ? pop() : nil
	}
	
	mutating func pop(where cond: (SwiftSymbol.Kind) -> Bool) -> SwiftSymbol? {
		return nameStack.last.map({ cond($0.kind) }) == true ? pop() : nil
	}
	
	mutating func popFunctionType(kind: SwiftSymbol.Kind, hasClangType: Bool = false) throws -> SwiftSymbol {
		var name = SwiftSymbol(kind: kind)
		if hasClangType {
			name.children.append(try demangleClangType())
		}
		if let sendingResult = pop(kind: .sendingResultFunctionType) {
			name.children.append(sendingResult)
		}
		if let isFunctionIsolation = pop(where: { $0 == .globalActorFunctionType || $0 == .isolatedAnyFunctionType }) {
			name.children.append(isFunctionIsolation)
		}
		if let differentiable = pop(kind: .differentiableFunctionType) {
			name.children.append(differentiable)
		}
		if let throwsAnnotation = pop(where: { $0 == .throwsAnnotation || $0 == .typedThrowsAnnotation}) {
			name.children.append(throwsAnnotation)
		}
		if let concurrent = pop(kind: .concurrentFunctionType) {
			name.children.append(concurrent)
		}
		if let asyncAnnotation = pop(kind: .asyncAnnotation) {
			name.children.append(asyncAnnotation)
		}
		name.children.append(try popFunctionParams(kind: .argumentTuple))
		name.children.append(try popFunctionParams(kind: .returnType))
		return SwiftSymbol(kind: .type, child: name)
	}
	
	mutating func popFunctionParams(kind: SwiftSymbol.Kind) throws -> SwiftSymbol {
		let paramsType: SwiftSymbol
		if pop(kind: .emptyList) != nil {
			return SwiftSymbol(kind: kind, child: SwiftSymbol(kind: .type, child: SwiftSymbol(kind: .tuple)))
		} else {
			paramsType = try require(pop(kind: .type))
		}
		
		if kind == .argumentTuple {
			let params = try require(paramsType.children.first)
			let numParams = params.kind == .tuple ? params.children.count : 1
			return SwiftSymbol(kind: kind, children: [paramsType], contents: .index(UInt64(numParams)))
		} else {
			return SwiftSymbol(kind: kind, children: [paramsType])
		}
	}
	
	mutating func getLabel(params: inout SwiftSymbol, idx: Int) throws -> SwiftSymbol {
		if isOldFunctionTypeMangling {
			let param = try require(params.children.at(idx))
			if let label = param.children.enumerated().first(where: { $0.element.kind == .tupleElementName }) {
				params.children[idx].children.remove(at: label.offset)
				return SwiftSymbol(kind: .identifier, contents: .name(label.element.text ?? ""))
			}
			return SwiftSymbol(kind: .firstElementMarker)
		}
		return try require(pop())
	}
	
	mutating func popFunctionParamLabels(type: SwiftSymbol) throws -> SwiftSymbol? {
		if !isOldFunctionTypeMangling && pop(kind: .emptyList) != nil {
			return SwiftSymbol(kind: .labelList)
		}
		
		guard type.kind == .type else { return nil }
		
		let topFuncType = try require(type.children.first)
		let funcType: SwiftSymbol
		if topFuncType.kind == .dependentGenericType {
			funcType = try require(topFuncType.children.at(1)?.children.first)
		} else {
			funcType = topFuncType
		}
		
		guard funcType.kind == .functionType || funcType.kind == .noEscapeFunctionType else { return nil }
		
		var firstChildIndex = 0
		if funcType.children.at(firstChildIndex)?.kind == .sendingResultFunctionType {
			firstChildIndex += 1
		}
		if funcType.children.at(firstChildIndex)?.kind == .globalActorFunctionType {
			firstChildIndex += 1
		}
		if funcType.children.at(firstChildIndex)?.kind == .isolatedAnyFunctionType {
			firstChildIndex += 1
		}
		if funcType.children.at(firstChildIndex)?.kind == .differentiableFunctionType {
			firstChildIndex += 1
		}
		if funcType.children.at(firstChildIndex)?.kind == .throwsAnnotation || funcType.children.at(0)?.kind == .typedThrowsAnnotation {
			firstChildIndex += 1
		}
		if funcType.children.at(firstChildIndex)?.kind == .asyncAnnotation {
			firstChildIndex += 1
		}
		
		let parameterType = try require(funcType.children.at(firstChildIndex))
		try require(parameterType.kind == .argumentTuple)
		
		let paramsType = try require(parameterType.children.first)
		try require(paramsType.kind == .type)
		
		let params = paramsType.children.first
		let numParams = params?.kind == .tuple ? (params?.children.count ?? 0) : 1
		
		guard numParams > 0 else { return nil }
		
		let possibleTuple = parameterType.children.first?.children.first
		guard !isOldFunctionTypeMangling, var tuple = possibleTuple, tuple.kind == .tuple else {
			return SwiftSymbol(kind: .labelList)
		}
		
		var hasLabels = false
		var children = [SwiftSymbol]()
		for i in 0..<numParams {
			let label = try getLabel(params: &tuple, idx: Int(i))
			try require(label.kind == .identifier || label.kind == .firstElementMarker)
			children.append(label)
			hasLabels = hasLabels || (label.kind != .firstElementMarker)
		}
		
		if !hasLabels {
			return SwiftSymbol(kind: .labelList)
		}
		
		return SwiftSymbol(kind: .labelList, children: isOldFunctionTypeMangling ? children : children.reversed())
	}
	
	mutating func popTuple() throws -> SwiftSymbol {
		var children: [SwiftSymbol] = []
		if pop(kind: .emptyList) == nil {
			var firstElem = false
			repeat {
				firstElem = pop(kind: .firstElementMarker) != nil
				var elemChildren: [SwiftSymbol] = pop(kind: .variadicMarker).map { [$0] } ?? []
				if let ident = pop(kind: .identifier), case .name(let text) = ident.contents {
					elemChildren.append(SwiftSymbol(kind: .tupleElementName, contents: .name(text)))
				}
				elemChildren.append(try require(pop(kind: .type)))
				children.insert(SwiftSymbol(kind: .tupleElement, children: elemChildren), at: 0)
			} while (!firstElem)
		}
		return SwiftSymbol(typeWithChildKind: .tuple, childChildren: children)
	}
	
	mutating func popPack(kind: SwiftSymbol.Kind = .pack) throws -> SwiftSymbol {
		if pop(kind: .emptyList) != nil {
			return SwiftSymbol(kind: .type, child: SwiftSymbol(kind: .pack))
		}
		var firstElem = false
		var children = [SwiftSymbol]()
		repeat {
			firstElem = pop(kind: .firstElementMarker) != nil
			try children.append(require(pop(kind: .type)))
		} while !firstElem
		children.reverse()
		return SwiftSymbol(kind: .type, child: SwiftSymbol(kind: .pack, children: children))
	}
	
	mutating func popSilPack() throws -> SwiftSymbol {
		switch try scanner.readScalar() {
		case "d": return try popPack(kind: .silPackDirect)
		case "i": return try popPack(kind: .silPackIndirect)
		default: throw failure
		}
	}
	
	mutating func popTypeList() throws -> SwiftSymbol {
		var children: [SwiftSymbol] = []
		if pop(kind: .emptyList) == nil {
			var firstElem = false
			repeat {
				firstElem = pop(kind: .firstElementMarker) != nil
				children.insert(try require(pop(kind: .type)), at: 0)
			} while (!firstElem)
		}
		return SwiftSymbol(kind: .typeList, children: children)
	}
	
	mutating func popProtocol() throws -> SwiftSymbol {
		if let type = pop(kind: .type) {
			try require(type.children.at(0)?.isProtocol == true)
			return type
		}
		
		if let symbolicRef = pop(kind: .protocolSymbolicReference) {
			return symbolicRef
		} else if let symbolicRef = pop(kind: .objectiveCProtocolSymbolicReference) {
			return symbolicRef
		}
		
		let name = try require(pop { $0.isDeclName })
		let context = try popContext()
		return SwiftSymbol(typeWithChildKind: .protocol, childChildren: [context, name])
	}
	
	mutating func popAnyProtocolConformanceList() throws -> SwiftSymbol {
		var conformanceList = SwiftSymbol(kind: .anyProtocolConformanceList)
		if pop(kind: .emptyList) == nil {
			var firstElem = false
			repeat {
				firstElem = pop(kind: .firstElementMarker) != nil
				conformanceList.children.append(try require(popAnyProtocolConformance()))
			} while !firstElem
			conformanceList.children = conformanceList.children.reversed()
		}
		return conformanceList
	}
	
	mutating func popAnyProtocolConformance() -> SwiftSymbol? {
		return pop { kind in
			switch kind {
			case .concreteProtocolConformance, .packProtocolConformance, .dependentProtocolConformanceRoot, .dependentProtocolConformanceInherited, .dependentProtocolConformanceAssociated: return true
			default: return false
			}
		}
	}
	
	mutating func demangleRetroactiveProtocolConformanceRef() throws -> SwiftSymbol {
		let module = try require(popModule())
		let proto = try require(popProtocol())
		return SwiftSymbol(kind: .protocolConformanceRefInOtherModule, children: [proto, module])
	}
	
	mutating func demangleConcreteProtocolConformance() throws -> SwiftSymbol {
		let conditionalConformanceList = try require(popAnyProtocolConformanceList())
		let conformanceRef = try pop(kind: .protocolConformanceRefInTypeModule) ?? pop(kind: .protocolConformanceRefInProtocolModule) ?? demangleRetroactiveProtocolConformanceRef()
		return SwiftSymbol(kind: .concreteProtocolConformance, children: [try require(pop(kind: .type)), conformanceRef, conditionalConformanceList])
	}
	
	mutating func popDependentProtocolConformance() -> SwiftSymbol? {
		return pop { kind in
			switch kind {
			case .dependentProtocolConformanceRoot, .dependentProtocolConformanceInherited, .dependentProtocolConformanceAssociated: return true
			default: return false
			}
		}
	}
	
	mutating func demangleDependentProtocolConformanceRoot() throws -> SwiftSymbol {
		let index = try demangleDependentConformanceIndex()
		let prot = try popProtocol()
		return SwiftSymbol(kind: .dependentProtocolConformanceRoot, children: [try require(pop(kind: .type)), prot, index])
	}
	
	mutating func demangleDependentProtocolConformanceInherited() throws -> SwiftSymbol {
		let index = try demangleDependentConformanceIndex()
		let prot = try popProtocol()
		let nested = try require(popDependentProtocolConformance())
		return SwiftSymbol(kind: .dependentProtocolConformanceInherited, children: [nested, prot, index])
	}
	
	mutating func popDependentAssociatedConformance() throws -> SwiftSymbol {
		let prot = try popProtocol()
		let dependentType = try require(pop(kind: .type))
		return SwiftSymbol(kind: .dependentAssociatedConformance, children: [dependentType, prot])
	}
	
	mutating func demangleDependentProtocolConformanceAssociated() throws -> SwiftSymbol {
		let index = try demangleDependentConformanceIndex()
		let assoc = try popDependentAssociatedConformance()
		let nested = try require(popDependentProtocolConformance())
		return SwiftSymbol(kind: .dependentProtocolConformanceAssociated, children: [nested, assoc, index])
	}
	
	mutating func demangleDependentConformanceIndex() throws -> SwiftSymbol {
		let index = try demangleIndex()
		if index == 1 {
			return SwiftSymbol(kind: .unknownIndex)
		}
		return SwiftSymbol(kind: .index, contents: .index(index - 2))
	}
	
	mutating func popModule() -> SwiftSymbol? {
		if let ident = pop(kind: .identifier) {
			return ident.changeKind(.module)
		} else {
			return pop(kind: .module)
		}
	}
	
	mutating func popContext() throws -> SwiftSymbol {
		if let mod = popModule() {
			return mod
		} else if let type = pop(kind: .type) {
			let child = try require(type.children.first)
			try require(child.kind.isContext)
			return child
		}
		return try require(pop { $0.isContext })
	}
	
	mutating func popTypeAndGetChild() throws -> SwiftSymbol {
		return try require(pop(kind: .type)?.children.first)
	}
	
	mutating func popTypeAndGetAnyGeneric() throws -> SwiftSymbol {
		let child = try popTypeAndGetChild()
		try require(child.kind.isAnyGeneric)
		return child
	}
	
	mutating func popAssociatedTypeName() throws -> SwiftSymbol {
		let maybeProto = pop(kind: .type)
		let proto: SwiftSymbol?
		if let p = maybeProto {
			try require(p.isProtocol)
			proto = p
		} else {
			proto = pop(kind: .protocolSymbolicReference) ?? pop(kind: .objectiveCProtocolSymbolicReference)
		}
		
		let id = try require(pop(kind: .identifier))
		if let p = proto {
			return SwiftSymbol(kind: .dependentAssociatedTypeRef, children: [id, p])
		} else {
			return SwiftSymbol(kind: .dependentAssociatedTypeRef, child: id)
		}
	}
	
	mutating func popAssociatedTypePath() throws -> SwiftSymbol {
		var firstElem = false
		var assocTypePath = [SwiftSymbol]()
		repeat {
			firstElem = pop(kind: .firstElementMarker) != nil
			assocTypePath.append(try require(popAssociatedTypeName()))
		} while !firstElem
		return SwiftSymbol(kind: .assocTypePath, children: assocTypePath.reversed())
	}
	
	mutating func popProtocolConformance() throws -> SwiftSymbol {
		let genSig = pop(kind: .dependentGenericSignature)
		let module = try require(popModule())
		let proto = try popProtocol()
		var type = pop(kind: .type)
		var ident: SwiftSymbol? = nil
		if type == nil {
			ident = pop(kind: .identifier)
			type = pop(kind: .type)
		}
		if let gs = genSig {
			type = SwiftSymbol(typeWithChildKind: .dependentGenericType, childChildren: [gs, try require(type)])
		}
		var children = [try require(type), proto, module]
		if let i = ident {
			children.append(i)
		}
		return SwiftSymbol(kind: .protocolConformance, children: children)
	}
	
	mutating func getDependentGenericParamType(depth: Int, index: Int) throws -> SwiftSymbol {
		try require(depth >= 0 && index >= 0)
		var charIndex = index
		var name = ""
		repeat {
			name.unicodeScalars.append(try require(UnicodeScalar(UnicodeScalar("A").value + UInt32(charIndex % 26))))
			charIndex /= 26
		} while charIndex != 0
		if depth != 0 {
			name = "\(name)\(depth)"
		}
		
		return SwiftSymbol(kind: .dependentGenericParamType, children: [
			SwiftSymbol(kind: .index, contents: .index(UInt64(depth))),
			SwiftSymbol(kind: .index, contents: .index(UInt64(index)))
		], contents: .name(name))
	}
	
	mutating func demangleStandardSubstitution() throws -> SwiftSymbol {
		switch try scanner.readScalar() {
		case "o": return SwiftSymbol(kind: .module, contents: .name(objcModule))
		case "C": return SwiftSymbol(kind: .module, contents: .name(cModule))
		case "g":
			let op = SwiftSymbol(typeWithChildKind: .boundGenericEnum, childChildren: [
				SwiftSymbol(swiftStdlibTypeKind: .enum, name: "Optional"),
				SwiftSymbol(kind: .typeList, child: try require(pop(kind: .type)))
			])
			substitutions.append(op)
			return op
		default:
			try scanner.backtrack()
			let repeatCount = try demangleNatural() ?? 0
			try require(repeatCount <= maxRepeatCount)
			let secondLevel = scanner.conditional(scalar: "c")
			let nd: SwiftSymbol
			if secondLevel {
				switch try scanner.readScalar() {
				case "A": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "Actor")
				case "C": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "CheckedContinuation")
				case "c": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "UnsafeContinuation")
				case "E": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "CancellationError")
				case "e": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "UnownedSerialExecutor")
				case "F": nd = SwiftSymbol(swiftStdlibTypeKind: .protocol, name: "Executor")
				case "f": nd = SwiftSymbol(swiftStdlibTypeKind: .protocol, name: "SerialExecutor")
				case "G": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "TaskGroup")
				case "g": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "ThrowingTaskGroup")
				case "h": nd = SwiftSymbol(swiftStdlibTypeKind: .protocol, name: "TaskExecutor")
				case "I": nd = SwiftSymbol(swiftStdlibTypeKind: .protocol, name: "AsyncIteratorProtocol")
				case "i": nd = SwiftSymbol(swiftStdlibTypeKind: .protocol, name: "AsyncSequence")
				case "J": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "UnownedJob")
				case "M": nd = SwiftSymbol(swiftStdlibTypeKind: .class, name: "MainActor")
				case "P": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "TaskPriority")
				case "S": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "AsyncStream")
				case "s": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "AsyncThrowingStream")
				case "T": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "Task")
				case "t": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "UnsafeCurrentTask")
				default: throw failure
				}
			} else {
				switch try scanner.readScalar() {
				case "a": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "Array")
				case "A": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "AutoreleasingUnsafeMutablePointer")
				case "b": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "Bool")
				case "c": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "UnicodeScalar")
				case "D": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "Dictionary")
				case "d": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "Double")
				case "f": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "Float")
				case "h": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "Set")
				case "I": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "DefaultIndices")
				case "i": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "Int")
				case "J": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "Character")
				case "N": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "ClosedRange")
				case "n": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "Range")
				case "O": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "ObjectIdentifier")
				case "p": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "UnsafeMutablePointer")
				case "P": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "UnsafePointer")
				case "R": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "UnsafeBufferPointer")
				case "r": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "UnsafeMutableBufferPointer")
				case "S": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "String")
				case "s": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "Substring")
				case "u": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "UInt")
				case "v": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "UnsafeMutableRawPointer")
				case "V": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "UnsafeRawPointer")
				case "W": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "UnsafeRawBufferPointer")
				case "w": nd = SwiftSymbol(swiftStdlibTypeKind: .structure, name: "UnsafeMutableRawBufferPointer")
					
				case "q": nd = SwiftSymbol(swiftStdlibTypeKind: .enum, name: "Optional")
					
				case "B": nd = SwiftSymbol(swiftStdlibTypeKind: .protocol, name: "BinaryFloatingPoint")
				case "E": nd = SwiftSymbol(swiftStdlibTypeKind: .protocol, name: "Encodable")
				case "e": nd = SwiftSymbol(swiftStdlibTypeKind: .protocol, name: "Decodable")
				case "F": nd = SwiftSymbol(swiftStdlibTypeKind: .protocol, name: "FloatingPoint")
				case "G": nd = SwiftSymbol(swiftStdlibTypeKind: .protocol, name: "RandomNumberGenerator")
				case "H": nd = SwiftSymbol(swiftStdlibTypeKind: .protocol, name: "Hashable")
				case "j": nd = SwiftSymbol(swiftStdlibTypeKind: .protocol, name: "Numeric")
				case "K": nd = SwiftSymbol(swiftStdlibTypeKind: .protocol, name: "BidirectionalCollection")
				case "k": nd = SwiftSymbol(swiftStdlibTypeKind: .protocol, name: "RandomAccessCollection")
				case "L": nd = SwiftSymbol(swiftStdlibTypeKind: .protocol, name: "Comparable")
				case "l": nd = SwiftSymbol(swiftStdlibTypeKind: .protocol, name: "Collection")
				case "M": nd = SwiftSymbol(swiftStdlibTypeKind: .protocol, name: "MutableCollection")
				case "m": nd = SwiftSymbol(swiftStdlibTypeKind: .protocol, name: "RangeReplaceableCollection")
				case "Q": nd = SwiftSymbol(swiftStdlibTypeKind: .protocol, name: "Equatable")
				case "T": nd = SwiftSymbol(swiftStdlibTypeKind: .protocol, name: "Sequence")
				case "t": nd = SwiftSymbol(swiftStdlibTypeKind: .protocol, name: "IteratorProtocol")
				case "U": nd = SwiftSymbol(swiftStdlibTypeKind: .protocol, name: "UnsignedInteger")
				case "X": nd = SwiftSymbol(swiftStdlibTypeKind: .protocol, name: "RangeExpression")
				case "x": nd = SwiftSymbol(swiftStdlibTypeKind: .protocol, name: "Strideable")
				case "Y": nd = SwiftSymbol(swiftStdlibTypeKind: .protocol, name: "RawRepresentable")
				case "y": nd = SwiftSymbol(swiftStdlibTypeKind: .protocol, name: "StringProtocol")
				case "Z": nd = SwiftSymbol(swiftStdlibTypeKind: .protocol, name: "SignedInteger")
				case "z": nd = SwiftSymbol(swiftStdlibTypeKind: .protocol, name: "BinaryInteger")
				default: throw failure
				}
			}
			if repeatCount > 1 {
				for _ in 0..<(repeatCount - 1) {
					nameStack.append(nd)
				}
			}
			return nd
		}
	}
	
	mutating func demangleIdentifier() throws -> SwiftSymbol {
		var hasWordSubs = false
		var isPunycoded = false
		let c = try scanner.read(where: { $0.isDigit })
		if c == "0" {
			if try scanner.readScalar() == "0" {
				isPunycoded = true
			} else {
				try scanner.backtrack()
				hasWordSubs = true
			}
		} else {
			try scanner.backtrack()
		}
		
		var identifier = ""
		repeat {
			while hasWordSubs && scanner.peek()?.isLetter == true {
				let c = try scanner.readScalar()
				var wordIndex = 0
				if c.isLower {
					wordIndex = Int(c.value - UnicodeScalar("a").value)
				} else {
					wordIndex = Int(c.value - UnicodeScalar("A").value)
					hasWordSubs = false
				}
				try require(wordIndex < maxNumWords)
				identifier.append(try require(words.at(wordIndex)))
			}
			if scanner.conditional(scalar: "0") {
				break
			}
			let numChars = try require(demangleNatural())
			try require(numChars > 0)
			if isPunycoded {
				_ = scanner.conditional(scalar: "_")
			}
			let text = try scanner.readScalars(count: Int(numChars))
			if isPunycoded {
				try identifier.append(decodeSwiftPunycode(text))
			} else {
				identifier.append(text)
				var word: String?
				for c in text.unicodeScalars {
					if word == nil, !c.isDigit && c != "_" && words.count < maxNumWords {
						word = "\(c)"
					} else if let w = word {
						if (c == "_") || (w.unicodeScalars.last?.isUpper == false && c.isUpper) {
							if w.unicodeScalars.count >= 2 {
								words.append(w)
							}
							if !c.isDigit && c != "_" && words.count < maxNumWords {
								word = "\(c)"
							} else {
								word = nil
							}
						} else {
							word?.unicodeScalars.append(c)
						}
					}
				}
				if let w = word, w.unicodeScalars.count >= 2 {
					words.append(w)
				}
			}
		} while hasWordSubs
		try require(!identifier.isEmpty)
		let result = SwiftSymbol(kind: .identifier, contents: .name(identifier))
		substitutions.append(result)
		return result
	}
	
	mutating func demangleOperatorIdentifier() throws -> SwiftSymbol {
		let ident = try require(pop(kind: .identifier))
		let opCharTable = Array("& @/= >    <*!|+?%-~   ^ .".unicodeScalars)
		
		var str = ""
		for c in (try require(ident.text)).unicodeScalars {
			if !c.isASCII {
				str.unicodeScalars.append(c)
			} else {
				try require(c.isLower)
				let o = try require(opCharTable.at(Int(c.value - UnicodeScalar("a").value)))
				try require(o != " ")
				str.unicodeScalars.append(o)
			}
		}
		switch try scanner.readScalar() {
		case "i": return SwiftSymbol(kind: .infixOperator, contents: .name(str))
		case "p": return SwiftSymbol(kind: .prefixOperator, contents: .name(str))
		case "P": return SwiftSymbol(kind: .postfixOperator, contents: .name(str))
		default: throw failure
		}
	}
	
	mutating func demangleLocalIdentifier() throws -> SwiftSymbol {
		let c = try scanner.readScalar()
		switch c {
		case "L":
			let discriminator = try require(pop(kind: .identifier))
			let name = try require(pop(where: { $0.isDeclName }))
			return SwiftSymbol(kind: .privateDeclName, children: [discriminator, name])
		case "l":
			let discriminator = try require(pop(kind: .identifier))
			return SwiftSymbol(kind: .privateDeclName, children: [discriminator])
		case "a"..."j", "A"..."J":
			return SwiftSymbol(kind: .relatedEntityDeclName, children: [try require(pop())], contents: .name(String(c)))
		default:
			try scanner.backtrack()
			let discriminator = try demangleIndexAsName()
			let name = try require(pop(where: { $0.isDeclName }))
			return SwiftSymbol(kind: .localDeclName, children: [discriminator, name])
		}
	}
	
	mutating func demangleBuiltinType() throws -> SwiftSymbol {
		let maxTypeSize: UInt64 = 4096
		switch try scanner.readScalar() {
		case "b": return SwiftSymbol(swiftBuiltinType: .builtinTypeName, name: "Builtin.BridgeObject")
		case "B": return SwiftSymbol(swiftBuiltinType: .builtinTypeName, name: "Builtin.UnsafeValueBuffer")
		case "e": return SwiftSymbol(swiftBuiltinType: .builtinTypeName, name: "Builtin.Executor")
		case "f":
			let size = try demangleIndex() - 1
			try require(size > 0 && size <= maxTypeSize)
			return SwiftSymbol(swiftBuiltinType: .builtinTypeName, name: "Builtin.FPIEEE\(size)")
		case "i":
			let size = try demangleIndex() - 1
			try require(size > 0 && size <= maxTypeSize)
			return SwiftSymbol(swiftBuiltinType: .builtinTypeName, name: "Builtin.Int\(size)")
		case "I": return SwiftSymbol(swiftBuiltinType: .builtinTypeName, name: "Builtin.IntLiteral")
		case "v":
			let elts = try demangleIndex() - 1
			try require(elts > 0 && elts <= maxTypeSize)
			let eltType = try popTypeAndGetChild()
			let text = try require(eltType.text)
			try require(eltType.kind == .builtinTypeName && text.starts(with: "Builtin.") == true)
			let name = text["Builtin.".endIndex...]
			return SwiftSymbol(swiftBuiltinType: .builtinTypeName, name: "Builtin.Vec\(elts)x\(name)")
		case "V":
			let element = try require(pop(kind: .type))
			let size = try require(pop(kind: .type))
			return SwiftSymbol(kind: .builtinFixedArray, children: [size, element])
		case "O": return SwiftSymbol(swiftBuiltinType: .builtinTypeName, name: "Builtin.UnknownObject")
		case "o": return SwiftSymbol(swiftBuiltinType: .builtinTypeName, name: "Builtin.NativeObject")
		case "p": return SwiftSymbol(swiftBuiltinType: .builtinTypeName, name: "Builtin.RawPointer")
		case "t": return SwiftSymbol(swiftBuiltinType: .builtinTypeName, name: "Builtin.SILToken")
		case "w": return SwiftSymbol(swiftBuiltinType: .builtinTypeName, name: "Builtin.Word")
		default: throw failure
		}
	}
	
	mutating func demangleAnyGenericType(kind: SwiftSymbol.Kind) throws -> SwiftSymbol {
		let name = try require(pop(where: { $0.isDeclName }))
		let ctx = try popContext()
		let type = SwiftSymbol(typeWithChildKind: kind, childChildren: [ctx, name])
		substitutions.append(type)
		return type
	}
	
	mutating func demangleExtensionContext() throws -> SwiftSymbol {
		let genSig = pop(kind: .dependentGenericSignature)
		let module = try require(popModule())
		let type = try popTypeAndGetAnyGeneric()
		if let g = genSig {
			return SwiftSymbol(kind: .extension, children: [module, type, g])
		} else {
			return SwiftSymbol(kind: .extension, children: [module, type])
		}
	}
	
	enum ManglingFlavor {
		case `default`
		case embedded
	}
	
	func getParentId(parent: SwiftSymbol, flavor: ManglingFlavor) -> String {
		return "{ParentId}"
	}
	
	mutating func setParentForOpaqueReturnTypeNodes(visited: inout SwiftSymbol, parentId: String) {
		if visited.kind == .opaqueReturnType {
			if visited.children.last?.kind == .opaqueReturnTypeParent {
				return
			}
			visited.children.append(SwiftSymbol(kind: .opaqueReturnTypeParent, contents: .name((parentId))))
			return
		}
		
		switch visited.kind {
		case .function, .variable, .subscript: return
		default: break
		}
		
		for index in visited.children.indices {
			setParentForOpaqueReturnTypeNodes(visited: &visited.children[index], parentId: parentId)
		}
	}
	
	mutating func demanglePlainFunction() throws -> SwiftSymbol {
		let genSig = pop(kind: .dependentGenericSignature)
		var type = try popFunctionType(kind: .functionType)
		let labelList = try popFunctionParamLabels(type: type)
		
		if let g = genSig {
			type = SwiftSymbol(typeWithChildKind: .dependentGenericType, childChildren: [g, type])
		}
		let name = try require(pop(where: { $0.isDeclName }))
		let ctx = try popContext()
		if let ll = labelList {
			return SwiftSymbol(kind: .function, children: [ctx, name, ll, type])
		}
		return SwiftSymbol(kind: .function, children: [ctx, name, type])
	}
	
	mutating func demangleRetroactiveConformance() throws -> SwiftSymbol {
		let index = try demangleIndexAsName()
		let conformance = try require(popAnyProtocolConformance())
		return SwiftSymbol(kind: .retroactiveConformance, children: [index, conformance])
	}
	
	mutating func demangleBoundGenericType() throws -> SwiftSymbol {
		let (array, retroactiveConformances) = try demangleBoundGenerics()
		let nominal = try popTypeAndGetAnyGeneric()
		var children = [try demangleBoundGenericArgs(nominal: nominal, array: array, index: 0)]
		if !retroactiveConformances.isEmpty {
			children.append(SwiftSymbol(kind: .typeList, children: retroactiveConformances.reversed()))
		}
		let type = SwiftSymbol(kind: .type, children: children)
		substitutions.append(type)
		return type
	}
	
	mutating func popRetroactiveConformances() throws -> SwiftSymbol? {
		var retroactiveConformances: [SwiftSymbol] = []
		while let conformance = pop(kind: .retroactiveConformance) {
			retroactiveConformances.append(conformance)
		}
		retroactiveConformances = retroactiveConformances.reversed()
		return retroactiveConformances.isEmpty ? nil : SwiftSymbol(kind: .typeList, children: retroactiveConformances)
	}
	
	mutating func demangleBoundGenerics() throws -> (typeLists: [SwiftSymbol], conformances: [SwiftSymbol]) {
		let retroactiveConformances = try popRetroactiveConformances()
		
		var array = [SwiftSymbol]()
		while true {
			var children = [SwiftSymbol]()
			while let t = pop(kind: .type) {
				children.append(t)
			}
			array.append(SwiftSymbol(kind: .typeList, children: children.reversed()))
			
			if pop(kind: .emptyList) != nil {
				break
			} else {
				_ = try require(pop(kind: .firstElementMarker))
			}
		}
		
		return (array, retroactiveConformances?.children ?? [])
	}
	
	mutating func demangleBoundGenericArgs(nominal: SwiftSymbol, array: [SwiftSymbol], index: Int) throws -> SwiftSymbol {
		if nominal.kind == .typeSymbolicReference || nominal.kind == .protocolSymbolicReference {
			let remaining = array.reversed().flatMap { $0.children }
			return SwiftSymbol(kind: .boundGenericOtherNominalType, children: [SwiftSymbol(kind: .type, child: nominal), SwiftSymbol(kind: .typeList, children: remaining)])
		}
		
		let context = try require(nominal.children.first)
		
		let consumesGenericArgs: Bool
		switch nominal.kind {
		case .variable, .subscript, .implicitClosure, .explicitClosure, .defaultArgumentInitializer, .initializer, .propertyWrapperBackingInitializer, .propertyWrapperInitFromProjectedValue, .static:
			consumesGenericArgs = false
		default:
			consumesGenericArgs = true
		}
		
		let args = try require(array.at(index))
		
		let n: SwiftSymbol
		let offsetIndex = index + (consumesGenericArgs ? 1 : 0)
		if offsetIndex < array.count {
			var boundParent: SwiftSymbol
			if context.kind == .extension {
				let p = try demangleBoundGenericArgs(nominal: try require(context.children.at(1)), array: array, index: offsetIndex)
				boundParent = SwiftSymbol(kind: .extension, children: [try require(context.children.first), p])
				if let thirdChild = context.children.at(2) {
					boundParent.children.append(thirdChild)
				}
			} else {
				boundParent = try demangleBoundGenericArgs(nominal: context, array: array, index: offsetIndex)
			}
			n = SwiftSymbol(kind: nominal.kind, children: [boundParent] + nominal.children.dropFirst())
		} else {
			n = nominal
		}
		
		if !consumesGenericArgs || args.children.count == 0 {
			return n
		}
		
		let kind: SwiftSymbol.Kind
		switch n.kind {
		case .class: kind = .boundGenericClass
		case .structure: kind = .boundGenericStructure
		case .enum: kind = .boundGenericEnum
		case .protocol: kind = .boundGenericProtocol
		case .otherNominalType: kind = .boundGenericOtherNominalType
		case .typeAlias: kind = .boundGenericTypeAlias
		case .function, .constructor: return SwiftSymbol(kind: .boundGenericFunction, children: [n, args])
		default: throw failure
		}
		
		return SwiftSymbol(kind: kind, children: [SwiftSymbol(kind: .type, child: n), args])
	}
	
	mutating func demangleImplParamConvention(kind: SwiftSymbol.Kind) throws -> SwiftSymbol? {
		let attr: String
		switch try scanner.readScalar() {
		case "i": attr = "@in"
		case "c": attr = "@in_constant"
		case "l": attr = "@inout"
		case "b": attr = "@inout_aliasable"
		case "n": attr = "@in_guaranteed"
		case "X": attr = "@in_cxx"
		case "x": attr = "@owned"
		case "g": attr = "@guaranteed"
		case "e": attr = "@deallocating"
		case "y": attr = "@unowned"
		case "v": attr = "@pack_owned"
		case "p": attr = "@pack_guaranteed"
		case "m": attr = "@pack_inout"
		default:
			try scanner.backtrack()
			return nil
		}
		return SwiftSymbol(kind: kind, child: SwiftSymbol(kind: .implConvention, contents: .name(attr)))
	}
	
	mutating func demangleImplResultConvention(kind: SwiftSymbol.Kind) throws -> SwiftSymbol? {
		let attr: String
		switch try scanner.readScalar() {
		case "r": attr = "@out"
		case "o": attr = "@owned"
		case "d": attr = "@unowned"
		case "u": attr = "@unowned_inner_pointer"
		case "a": attr = "@autoreleased"
		case "k": attr = "@pack_out"
		default:
			try scanner.backtrack()
			return nil
		}
		return SwiftSymbol(kind: kind, child: SwiftSymbol(kind: .implConvention, contents: .name(attr)))
	}
	
	mutating func demangleImplParameterSending() -> SwiftSymbol? {
		guard scanner.conditional(scalar: "T") else {
			return nil
		}
		return SwiftSymbol(kind: .implParameterSending, contents: .name("sending"))
	}
	
	mutating func demangleImplResultDifferentiability() -> SwiftSymbol {
		return SwiftSymbol(kind: .implParameterResultDifferentiability, contents: .name(scanner.conditional(scalar: "w") ? "@noDerivative" : ""))
	}
	
	mutating func demangleClangType() throws -> SwiftSymbol {
		let numChars = try require(demangleNatural())
		let text = try scanner.readScalars(count: Int(numChars))
		return SwiftSymbol(kind: .clangType, contents: .name(text))
	}
	
	mutating func demangleImplFunctionType() throws -> SwiftSymbol {
		var typeChildren = [SwiftSymbol]()
		if scanner.conditional(scalar: "s") {
			let (substitutions, conformances) = try demangleBoundGenerics()
			let sig = try require(pop(kind: .dependentGenericSignature))
			let subsNode = SwiftSymbol(kind: .implPatternSubstitutions, children: [sig, try require(substitutions.first)] + conformances)
			typeChildren.append(subsNode)
		}
		
		if scanner.conditional(scalar: "I") {
			let (substitutions, conformances) = try demangleBoundGenerics()
			let subsNode = SwiftSymbol(kind: .implInvocationSubstitutions, children: [try require(substitutions.first)] + conformances)
			typeChildren.append(subsNode)
		}
		
		var genSig = pop(kind: .dependentGenericSignature)
		if let g = genSig, scanner.conditional(scalar: "P") {
			genSig = g.changeKind(.dependentPseudogenericSignature)
		}
		
		if scanner.conditional(scalar: "e") {
			typeChildren.append(SwiftSymbol(kind: .implEscaping))
		}
		
		if scanner.conditional(scalar: "A") {
			typeChildren.append(SwiftSymbol(kind: .implErasedIsolation))
		}
		
		if let peek = scanner.peek(), let differentiability = Differentiability(rawValue: peek) {
			try scanner.skip()
			typeChildren.append(SwiftSymbol(kind: .implDifferentiabilityKind, contents: .index(UInt64(differentiability.rawValue))))
		}
		
		let cAttr: String
		switch try scanner.readScalar() {
		case "y": cAttr = "@callee_unowned"
		case "g": cAttr = "@callee_guaranteed"
		case "x": cAttr = "@callee_owned"
		case "t": cAttr = "@convention(thin)"
		default: throw failure
		}
		typeChildren.append(SwiftSymbol(kind: .implConvention, contents: .name(cAttr)))
		
		let fConv: String?
		var hasClangType = false
		switch try scanner.readScalar() {
		case "B": fConv = "block"
		case "C": fConv = "c"
		case "z":
			if scanner.conditional(scalar: "B") {
				hasClangType = true
				fConv = "block"
			} else if scanner.conditional(scalar: "C") {
				hasClangType = true
				fConv = "c"
			} else {
				fConv = nil
			}
		case "M": fConv = "method"
		case "O": fConv = "objc_method"
		case "K": fConv = "closure"
		case "W": fConv = "witness_method"
		default:
			try scanner.backtrack()
			fConv = nil
		}
		if let fConv {
			var node = SwiftSymbol(kind: .implFunctionConvention, child: SwiftSymbol(kind: .implFunctionConventionName, contents: .name(fConv)))
			if hasClangType {
				try node.children.append(demangleClangType())
			}
			typeChildren.append(node)
		}
		
		if scanner.conditional(scalar: "A") {
			typeChildren.append(SwiftSymbol(kind: .implCoroutineKind, contents: .name("yield_once")))
		} else if scanner.conditional(scalar: "I") {
			typeChildren.append(SwiftSymbol(kind: .implCoroutineKind, contents: .name("yield_once_2")))
		} else if scanner.conditional(scalar: "G") {
			typeChildren.append(SwiftSymbol(kind: .implCoroutineKind, contents: .name("yield_many")))
		}
		
		if scanner.conditional(scalar: "h") {
			typeChildren.append(SwiftSymbol(kind: .implFunctionAttribute, contents: .name("@Sendable")))
		}
		
		if scanner.conditional(scalar: "H") {
			typeChildren.append(SwiftSymbol(kind: .implFunctionAttribute, contents: .name("@async")))
		}
		
		if scanner.conditional(scalar: "T") {
			typeChildren.append(SwiftSymbol(kind: .implSendingResult))
		}
		
		if let g = genSig {
			typeChildren.append(g)
		}
		
		var numTypesToAdd = 0
		while var param = try demangleImplParamConvention(kind: .implParameter) {
			param.children.append(demangleImplResultDifferentiability())
			if let diff = demangleImplParameterSending() {
				param.children.append(diff)
			}
			typeChildren.append(param)
			numTypesToAdd += 1
		}
		while var result = try demangleImplResultConvention(kind: .implResult) {
			result.children.append(demangleImplResultDifferentiability())
			typeChildren.append(result)
			numTypesToAdd += 1
		}
		while scanner.conditional(scalar: "Y") {
			typeChildren.append(try require(demangleImplParamConvention(kind: .implYield)))
			numTypesToAdd += 1
		}
		if scanner.conditional(scalar: "z") {
			typeChildren.append(try require(demangleImplResultConvention(kind: .implErrorResult)))
			numTypesToAdd += 1
		}
		try scanner.match(scalar: "_")
		for i in 0..<numTypesToAdd {
			try require(typeChildren.indices.contains(typeChildren.count - i - 1))
			typeChildren[typeChildren.count - i - 1].children.append(try require(pop(kind: .type)))
		}
		
		return SwiftSymbol(typeWithChildKind: .implFunctionType, childChildren: typeChildren)
	}
	
	mutating func demangleMetatype() throws -> SwiftSymbol {
		switch try scanner.readScalar() {
		case "a": return SwiftSymbol(kind: .typeMetadataAccessFunction, child: try require(pop(kind: .type)))
		case "A": return SwiftSymbol(kind: .reflectionMetadataAssocTypeDescriptor, child: try popProtocolConformance())
		case "b": return SwiftSymbol(kind: .canonicalSpecializedGenericTypeMetadataAccessFunction, child: try require(pop(kind: .type)))
		case "B": return SwiftSymbol(kind: .reflectionMetadataBuiltinDescriptor, child: try require(pop(kind: .type)))
		case "c": return SwiftSymbol(kind: .protocolConformanceDescriptor, child: try require(popProtocolConformance()))
		case "C":
			let t = try require(pop(kind: .type))
			try require(t.children.first?.kind.isAnyGeneric == true)
			return SwiftSymbol(kind: .reflectionMetadataSuperclassDescriptor, child: try require(t.children.first))
		case "D": return SwiftSymbol(kind: .typeMetadataDemanglingCache, child: try require(pop(kind: .type)))
		case "f": return SwiftSymbol(kind: .fullTypeMetadata, child: try require(pop(kind: .type)))
		case "F": return SwiftSymbol(kind: .reflectionMetadataFieldDescriptor, child: try require(pop(kind: .type)))
		case "g": return SwiftSymbol(kind: .opaqueTypeDescriptorAccessor, child: try require(pop()))
		case "h": return SwiftSymbol(kind: .opaqueTypeDescriptorAccessorImpl, child: try require(pop()))
		case "i": return SwiftSymbol(kind: .typeMetadataInstantiationFunction, child: try require(pop(kind: .type)))
		case "I": return SwiftSymbol(kind: .typeMetadataInstantiationCache, child: try require(pop(kind: .type)))
		case "j": return SwiftSymbol(kind: .opaqueTypeDescriptorAccessorKey, child: try require(pop()))
		case "J": return SwiftSymbol(kind: .noncanonicalSpecializedGenericTypeMetadataCache, child: try require(pop()))
		case "k": return SwiftSymbol(kind: .opaqueTypeDescriptorAccessorVar, child: try require(pop()))
		case "K": return SwiftSymbol(kind: .metadataInstantiationCache, child: try require(pop()))
		case "l": return SwiftSymbol(kind: .typeMetadataSingletonInitializationCache, child: try require(pop(kind: .type)))
		case "L": return SwiftSymbol(kind: .typeMetadataLazyCache, child: try require(pop(kind: .type)))
		case "m": return SwiftSymbol(kind: .metaclass, child: try require(pop(kind: .type)))
		case "M": return SwiftSymbol(kind: .canonicalSpecializedGenericMetaclass, child: try require(pop(kind: .type)))
		case "n": return SwiftSymbol(kind: .nominalTypeDescriptor, child: try require(pop(kind: .type)))
		case "N": return SwiftSymbol(kind: .noncanonicalSpecializedGenericTypeMetadata, child: try require(pop(kind: .type)))
		case "o": return SwiftSymbol(kind: .classMetadataBaseOffset, child: try require(pop(kind: .type)))
		case "p": return SwiftSymbol(kind: .protocolDescriptor, child: try popProtocol())
		case "P": return SwiftSymbol(kind: .genericTypeMetadataPattern, child: try require(pop(kind: .type)))
		case "q": return SwiftSymbol(kind: .uniquable, child: try require(pop()))
		case "Q": return SwiftSymbol(kind: .opaqueTypeDescriptor, child: try require(pop()))
		case "r": return SwiftSymbol(kind: .typeMetadataCompletionFunction, child: try require(pop(kind: .type)))
		case "s": return SwiftSymbol(kind: .objCResilientClassStub, child: try require(popProtocol()))
		case "S": return SwiftSymbol(kind: .protocolSelfConformanceDescriptor, child: try require(pop(kind: .type)))
		case "t": return SwiftSymbol(kind: .fullObjCResilientClassStub, child: try require(pop(kind: .type)))
		case "u": return SwiftSymbol(kind: .methodLookupFunction, child: try require(pop(kind: .type)))
		case "U": return SwiftSymbol(kind: .objCMetadataUpdateFunction, child: try require(pop(kind: .type)))
		case "V": return SwiftSymbol(kind: .propertyDescriptor, child: try require(pop { $0.isEntity }))
		case "X": return try demanglePrivateContextDescriptor()
		case "z": return SwiftSymbol(kind: .canonicalPrespecializedGenericTypeCachingOnceToken, child: try require(pop(kind: .type)))
		default: throw failure
		}
	}
	
	mutating func demanglePrivateContextDescriptor() throws -> SwiftSymbol {
		switch try scanner.readScalar() {
		case "E": return SwiftSymbol(kind: .extensionDescriptor, child: try popContext())
		case "M": return SwiftSymbol(kind: .moduleDescriptor, child: try require(popModule()))
		case "Y":
			let discriminator = try require(pop())
			let context = try popContext()
			return SwiftSymbol(kind: .anonymousDescriptor, children: [context, discriminator])
		case "X": return SwiftSymbol(kind: .anonymousDescriptor, child: try popContext())
		case "A":
			let path = try require(popAssociatedTypePath())
			let base = try require(pop(kind: .type))
			return SwiftSymbol(kind: .associatedTypeGenericParamRef, children: [base, path])
		default: throw failure
		}
	}
	
	mutating func demangleArchetype() throws -> SwiftSymbol {
		switch try scanner.readScalar() {
		case "a":
			let ident = try require(pop(kind: .identifier))
			let arch = try popTypeAndGetChild()
			let assoc = SwiftSymbol(typeWithChildKind: .associatedTypeRef, childChildren: [arch, ident])
			substitutions.append(assoc)
			return assoc
		case "O":
			return SwiftSymbol(kind: .opaqueReturnTypeOf, child: try popContext())
		case "o":
			let index = try demangleIndex()
			let (boundGenericArgs, retroactiveConformances) = try demangleBoundGenerics()
			let name = try require(pop())
			let opaque = SwiftSymbol(
				kind: .opaqueType,
				children: [
					name,
					SwiftSymbol(kind: .index, contents: .index(index)),
					SwiftSymbol(kind: .typeList, children: boundGenericArgs + retroactiveConformances)
				]
			)
			let opaqueType = SwiftSymbol(kind: .type, child: opaque)
			substitutions.append(opaqueType)
			return opaqueType
		case "r":
			return SwiftSymbol(typeWithChildKind: .opaqueReturnType, childChildren: [])
		case "x":
			let t = try demangleAssociatedTypeSimple(index: nil)
			substitutions.append(t)
			return t
		case "X":
			let t = try demangleAssociatedTypeCompound(index: nil)
			substitutions.append(t)
			return t
		case "y":
			let t = try demangleAssociatedTypeSimple(index: demangleGenericParamIndex())
			substitutions.append(t)
			return t
		case "Y":
			let t = try demangleAssociatedTypeCompound(index: demangleGenericParamIndex())
			substitutions.append(t)
			return t
		case "z":
			let t = try demangleAssociatedTypeSimple(index: getDependentGenericParamType(depth: 0, index: 0))
			substitutions.append(t)
			return t
		case "Z":
			let t = try demangleAssociatedTypeCompound(index: getDependentGenericParamType(depth: 0, index: 0))
			substitutions.append(t)
			return t
		case "p":
			let count = try popTypeAndGetChild()
			let pattern = try popTypeAndGetChild()
			return SwiftSymbol(kind: .type, child: SwiftSymbol(kind: .packExpansion, children: [pattern, count]))
		case "e":
			let pack = try popTypeAndGetChild()
			let level = try demangleIndex()
			return SwiftSymbol(kind: .type, child: SwiftSymbol(kind: .packElement, children: [pack, SwiftSymbol(kind: .packElementLevel, contents: .index(level))]))
		case "P":
			return try popPack()
		case "S":
			return try popSilPack()
		default: throw failure
		}
	}
	
	mutating func demangleAssociatedTypeSimple(index: SwiftSymbol?) throws -> SwiftSymbol {
		let atName = try popAssociatedTypeName()
		let gpi = try index.map { SwiftSymbol(kind: .type, child: $0) } ?? require(pop(kind: .type))
		return SwiftSymbol(typeWithChildKind: .dependentMemberType, childChildren: [gpi, atName])
	}
	
	mutating func demangleAssociatedTypeCompound(index: SwiftSymbol?) throws -> SwiftSymbol {
		var assocTypeNames = [SwiftSymbol]()
		var firstElem = false
		repeat {
			firstElem = pop(kind: .firstElementMarker) != nil
			assocTypeNames.append(try popAssociatedTypeName())
		} while !firstElem
		
		var base = try index.map { SwiftSymbol(kind: .type, child: $0) } ?? require(pop(kind: .type))
		while let assocType = assocTypeNames.popLast() {
			base = SwiftSymbol(kind: .type, child: SwiftSymbol(kind: .dependentMemberType, children: [SwiftSymbol(kind: .type, child: base), assocType]))
		}
		return base
	}
	
	mutating func demangleGenericParamIndex() throws -> SwiftSymbol {
		switch try scanner.readScalar() {
		case "d":
			let depth = try demangleIndex() + 1
			let index = try demangleIndex()
			return try getDependentGenericParamType(depth: Int(depth), index: Int(index))
		case "z":
			return try getDependentGenericParamType(depth: 0, index: 0)
		case "s":
			return SwiftSymbol(kind: .constrainedExistentialSelf)
		default:
			try scanner.backtrack()
			return try getDependentGenericParamType(depth: 0, index: Int(demangleIndex() + 1))
		}
	}
	
	mutating func demangleThunkOrSpecialization() throws -> SwiftSymbol {
		let c = try scanner.readScalar()
		switch c {
		case "T":
			switch try scanner.readScalar() {
			case "I": return try SwiftSymbol(kind: .silThunkIdentity, child: require(pop(where: { $0.isEntity })))
			case "H": return try SwiftSymbol(kind: .silThunkHopToMainActorIfNeeded, child: require(pop(where: { $0.isEntity })))
			default: throw failure
			}
		case "c": return SwiftSymbol(kind: .curryThunk, child: try require(pop(where: { $0.isEntity })))
		case "j": return SwiftSymbol(kind: .dispatchThunk, child: try require(pop(where: { $0.isEntity })))
		case "q": return SwiftSymbol(kind: .methodDescriptor, child: try require(pop(where: { $0.isEntity })))
		case "o": return SwiftSymbol(kind: .objCAttribute)
		case "O": return SwiftSymbol(kind: .nonObjCAttribute)
		case "D": return SwiftSymbol(kind: .dynamicAttribute)
		case "d": return SwiftSymbol(kind: .directMethodReferenceAttribute)
		case "E": return SwiftSymbol(kind: .distributedThunk)
		case "F": return SwiftSymbol(kind: .distributedAccessor)
		case "a": return SwiftSymbol(kind: .partialApplyObjCForwarder)
		case "A": return SwiftSymbol(kind: .partialApplyForwarder)
		case "m": return SwiftSymbol(kind: .mergedFunction)
		case "X": return SwiftSymbol(kind: .dynamicallyReplaceableFunctionVar)
		case "x": return SwiftSymbol(kind: .dynamicallyReplaceableFunctionKey)
		case "I": return SwiftSymbol(kind: .dynamicallyReplaceableFunctionImpl)
		case "Y": return SwiftSymbol(kind: .asyncSuspendResumePartialFunction, child: try demangleIndexAsName())
		case "Q": return SwiftSymbol(kind: .asyncAwaitResumePartialFunction, child: try demangleIndexAsName())
		case "C": return SwiftSymbol(kind: .coroutineContinuationPrototype, child: try require(pop(kind: .type)))
		case "z": fallthrough
		case "Z":
			let flagMode = try demangleIndexAsName()
			let sig = pop(kind: .dependentGenericSignature)
			let resultType = try require(pop(kind: .type))
			let implType = try require(pop(kind: .type))
			var node = SwiftSymbol(kind: c == "z" ? .objCAsyncCompletionHandlerImpl : .predefinedObjCAsyncCompletionHandlerImpl, children: [implType, resultType, flagMode])
			if let sig {
				node.children.append(sig)
			}
			return node
		case "V":
			let base = try require(pop(where: { $0.isEntity }))
			let derived = try require(pop(where: { $0.isEntity }))
			return SwiftSymbol(kind: .vTableThunk, children: [derived, base])
		case "W":
			let entity = try require(pop(where: { $0.isEntity }))
			let conf = try popProtocolConformance()
			return SwiftSymbol(kind: .protocolWitness, children: [conf, entity])
		case "S":
			return try SwiftSymbol(kind: .protocolSelfConformanceWitness, child: require(pop(where: { $0.isEntity })))
		case "R", "r", "y":
			let kind = switch c {
			case "R": SwiftSymbol.Kind.reabstractionThunkHelper
			case "y": SwiftSymbol.Kind.reabstractionThunkHelperWithSelf
			default: SwiftSymbol.Kind.reabstractionThunk
			}
			var name = SwiftSymbol(kind: kind)
			if let genSig = pop(kind: .dependentGenericSignature) {
				name.children.append(genSig)
			}
			if kind == .reabstractionThunkHelperWithSelf {
				name.children.append(try require(pop(kind: .type)))
			}
			name.children.append(try require(pop(kind: .type)))
			name.children.append(try require(pop(kind: .type)))
			return name
		case "g": return try demangleGenericSpecialization(kind: .genericSpecialization)
		case "G": return try demangleGenericSpecialization(kind: .genericSpecializationNotReAbstracted)
		case "B": return try demangleGenericSpecialization(kind: .genericSpecializationInResilienceDomain)
		case "t": return try demangleGenericSpecializationWithDroppedArguments()
		case "s": return try demangleGenericSpecialization(kind: .genericSpecializationPrespecialized)
		case "i": return try demangleGenericSpecialization(kind: .inlinedGenericFunction)
		case "P", "p":
			var spec = try demangleSpecAttributes(kind: c == "P" ? .genericPartialSpecializationNotReAbstracted : .genericPartialSpecialization)
			let param = SwiftSymbol(kind: .genericSpecializationParam, child: try require(pop(kind: .type)))
			spec.children.append(param)
			return spec
		case "f": return try demangleFunctionSpecialization()
		case "K", "k":
			let nodeKind: SwiftSymbol.Kind = c == "K" ? .keyPathGetterThunkHelper : .keyPathSetterThunkHelper
			let isSerialized = scanner.conditional(string: "q")
			var types = [SwiftSymbol]()
			var node = pop(kind: .type)
			while let n = node {
				types.append(n)
				node = pop(kind: .type)
			}
			var result: SwiftSymbol
			if let n = pop() {
				if n.kind == .dependentGenericSignature {
					let decl = try require(pop())
					result = SwiftSymbol(kind: nodeKind, children: [decl, n])
				} else {
					result = SwiftSymbol(kind: nodeKind, child: n)
				}
			} else {
				throw failure
			}
			for t in types {
				result.children.append(t)
			}
			if isSerialized {
				result.children.append(SwiftSymbol(kind: .isSerialized))
			}
			return result
		case "l": return SwiftSymbol(kind: .associatedTypeDescriptor, child: try require(popAssociatedTypeName()))
		case "L": return SwiftSymbol(kind: .protocolRequirementsBaseDescriptor, child: try require(popProtocol()))
		case "M": return SwiftSymbol(kind: .defaultAssociatedTypeMetadataAccessor, child: try require(popAssociatedTypeName()))
		case "n":
			let requirement = try popProtocol()
			let associatedTypePath = try popAssociatedTypePath()
			let protocolType = try require(pop(kind: .type))
			return SwiftSymbol(kind: .associatedConformanceDescriptor, children: [protocolType, associatedTypePath, requirement])
		case "N":
			let requirement = try popProtocol()
			let associatedTypePath = try popAssociatedTypePath()
			let protocolType = try require(pop(kind: .type))
			return SwiftSymbol(kind: .defaultAssociatedConformanceAccessor, children: [protocolType, associatedTypePath, requirement])
		case "b":
			let requirement = try popProtocol()
			let protocolType = try require(pop(kind: .type))
			return SwiftSymbol(kind: .baseConformanceDescriptor, children: [protocolType, requirement])
		case "H", "h":
			let nodeKind: SwiftSymbol.Kind = c == "H" ? .keyPathEqualsThunkHelper : .keyPathHashThunkHelper
			let isSerialized = scanner.peek() == "q"
			var types = [SwiftSymbol]()
			let node = try require(pop())
			var genericSig: SwiftSymbol? = nil
			if node.kind == .dependentGenericSignature {
				genericSig = node
			} else if node.kind == .type {
				types.append(node)
			} else {
				throw failure
			}
			while let n = pop() {
				try require(n.kind == .type)
				types.append(n)
			}
			var result = SwiftSymbol(kind: nodeKind)
			for t in types {
				result.children.append(t)
			}
			if let gs = genericSig {
				result.children.append(gs)
			}
			if isSerialized {
				result.children.append(SwiftSymbol(kind: .isSerialized))
			}
			return result
		case "v":
			let index = try demangleIndex()
			if scanner.conditional(scalar: "r") {
				return SwiftSymbol(kind: .outlinedReadOnlyObject, contents: .index(index))
			} else {
				return SwiftSymbol(kind: .outlinedVariable, contents: .index(index))
			}
		case "e": return SwiftSymbol(kind: .outlinedBridgedMethod, contents: .name(try demangleBridgedMethodParams()))
		case "u": return SwiftSymbol(kind: .asyncFunctionPointer)
		case "U":
			let globalActor = try require(pop(kind: .type))
			let reabstraction = try require(pop())
			return SwiftSymbol(kind: .reabstractionThunkHelperWithGlobalActor, children: [reabstraction, globalActor])
		case "J":
			switch try scanner.readScalar() {
			case "S": return try demangleAutoDiffSubsetParametersThunk()
			case "O": return try demangleAutoDiffSelfReorderingReabstractionThunk()
			case "V": return try demangleAutoDiffFunctionOrSimpleThunk(kind: .autoDiffDerivativeVTableThunk)
			default:
				try scanner.backtrack()
				return try demangleAutoDiffFunctionOrSimpleThunk(kind: .autoDiffFunction)
			}
		case "w":
			switch try scanner.readScalar() {
			case "b": return SwiftSymbol(kind: .backDeploymentThunk)
			case "B": return SwiftSymbol(kind: .backDeploymentFallback)
			case "S": return SwiftSymbol(kind: .hasSymbolQuery)
			default: throw failure
			}
		default: throw failure
		}
	}
	
	mutating func demangleAutoDiffFunctionOrSimpleThunk(kind: SwiftSymbol.Kind) throws -> SwiftSymbol {
		var result = SwiftSymbol(kind: kind)
		while let node = pop() {
			result.children.append(node)
		}
		result.children.reverse()
		let kind = try demangleAutoDiffFunctionKind()
		result.children.append(kind)
		result.children.append(try require(demangleIndexSubset()))
		try scanner.match(scalar: "p")
		result.children.append(try require(demangleIndexSubset()))
		try scanner.match(scalar: "r")
		return result
	}
	
	mutating func demangleAutoDiffFunctionKind() throws -> SwiftSymbol {
		let kind = try scanner.readScalar()
		guard let autoDiffFunctionKind = AutoDiffFunctionKind(UInt64(kind.value)) else {
			throw failure
		}
		return SwiftSymbol(kind: .autoDiffFunctionKind, contents: .index(UInt64(autoDiffFunctionKind.rawValue.value)))
	}
	
	mutating func demangleAutoDiffSubsetParametersThunk() throws -> SwiftSymbol {
		var result = SwiftSymbol(kind: .autoDiffSubsetParametersThunk)
		while let node = pop() {
			result.children.append(node)
		}
		result.children.reverse()
		let kind = try demangleAutoDiffFunctionKind()
		result.children.append(kind)
		result.children.append(try require(demangleIndexSubset()))
		try scanner.match(scalar: "p")
		result.children.append(try require(demangleIndexSubset()))
		try scanner.match(scalar: "r")
		result.children.append(try require(demangleIndexSubset()))
		try scanner.match(scalar: "P")
		return result
	}
	
	mutating func demangleAutoDiffSelfReorderingReabstractionThunk() throws -> SwiftSymbol {
		var result = SwiftSymbol(kind: .autoDiffSelfReorderingReabstractionThunk)
		if let dependentGenericSignature = pop(kind: .dependentGenericSignature) {
			result.children.append(dependentGenericSignature)
		}
		result.children.append(try require(pop(kind: .type)))
		result.children.append(try require(pop(kind: .type)))
		result.children.reverse()
		result.children.append(try demangleAutoDiffFunctionKind())
		return result
	}
	
	mutating func demangleDifferentiabilityWitness() throws -> SwiftSymbol {
		var result = SwiftSymbol(kind: .differentiabilityWitness)
		let optionalGenSig = pop(kind: .dependentGenericSignature)
		while let node = pop() {
			result.children.append(node)
		}
		result.children.reverse()
		let kind: Differentiability = switch try scanner.readScalar() {
		case "f": .forward
		case "r": .reverse
		case "d": .normal
		case "l": .linear
		default: throw failure
		}
		result.children.append(SwiftSymbol(kind: .index, contents: .index(UInt64(kind.rawValue.value))))
		result.children.append(try require(demangleIndexSubset()))
		try scanner.match(scalar: "p")
		result.children.append(try require(demangleIndexSubset()))
		try scanner.match(scalar: "r")
		if let optionalGenSig {
			result.children.append(optionalGenSig)
		}
		return result
	}
	
	mutating func demangleIndexSubset() throws -> SwiftSymbol {
		var str = ""
		while let c = scanner.conditional(where: { $0 == "S" || $0 == "U" }) {
			str.unicodeScalars.append(c)
		}
		try require(!str.isEmpty)
		return SwiftSymbol(kind: .indexSubset, contents: .name(str))
	}
	
	mutating func demangleDifferentiableFunctionType() throws -> SwiftSymbol {
		let kind: Differentiability = switch try scanner.readScalar() {
		case "f": .forward
		case "r": .reverse
		case "d": .normal
		case "l": .linear
		default: throw failure
		}
		return SwiftSymbol(kind: .differentiableFunctionType, contents: .index(UInt64(kind.rawValue.value)))
		
	}
	
	mutating func demangleBridgedMethodParams() throws -> String {
		if scanner.conditional(scalar: "_") {
			return ""
		}
		var str = ""
		let kind = try scanner.readScalar()
		switch kind {
		case "p", "a", "m": str.unicodeScalars.append(kind)
		default: return ""
		}
		while !scanner.conditional(scalar: "_") {
			let c = try scanner.readScalar()
			try require(c == "n" || c == "b" || c == "g")
			str.unicodeScalars.append(c)
		}
		return str
	}
	
	mutating func demangleGenericSpecialization(kind: SwiftSymbol.Kind, droppedArguments: SwiftSymbol? = nil) throws -> SwiftSymbol {
		var spec = try demangleSpecAttributes(kind: kind)
		if let droppedArguments {
			spec.children.append(contentsOf: droppedArguments.children)
		}
		let list = try popTypeList()
		for t in list.children {
			spec.children.append(SwiftSymbol(kind: .genericSpecializationParam, child: t))
		}
		return spec
	}
	
	mutating func demangleGenericSpecializationWithDroppedArguments() throws -> SwiftSymbol {
		try scanner.backtrack()
		var tmp = SwiftSymbol(kind: .genericSpecialization)
		while scanner.conditional(scalar: "t") {
			let n = try demangleNatural().map { SwiftSymbol.Contents.index($0 + 1) } ?? SwiftSymbol.Contents.index(0)
			tmp.children.append(SwiftSymbol(kind: .droppedArgument, contents: n))
		}
		let kind: SwiftSymbol.Kind = switch try scanner.readScalar() {
		case "g": .genericSpecialization
		case "G": .genericSpecializationNotReAbstracted
		case "B": .genericSpecializationInResilienceDomain
		default: throw failure
		}
		return try demangleGenericSpecialization(kind: kind, droppedArguments: tmp)
	}
	
	mutating func demangleFunctionSpecialization() throws -> SwiftSymbol {
		var spec = try demangleSpecAttributes(kind: .functionSignatureSpecialization, demangleUniqueId: true)
		var paramIdx: UInt64 = 0
		while !scanner.conditional(scalar: "_") {
			spec.children.append(try demangleFuncSpecParam(kind: .functionSignatureSpecializationParam))
			paramIdx += 1
		}
		if !scanner.conditional(scalar: "n") {
			spec.children.append(try demangleFuncSpecParam(kind: .functionSignatureSpecializationReturn))
		}
		
		for paramIndexPair in spec.children.enumerated().reversed() {
			var param = paramIndexPair.element
			guard param.kind == .functionSignatureSpecializationParam else { continue }
			guard let kindName = param.children.first else { continue }
			guard kindName.kind == .functionSignatureSpecializationParamKind, case .index(let i) = kindName.contents, let paramKind = FunctionSigSpecializationParamKind(rawValue: UInt64(i)) else { throw failure }
			switch paramKind {
			case .constantPropFunction, .constantPropGlobal, .constantPropString, .constantPropKeyPath, .closureProp:
				let fixedChildrenEndIndex = param.children.endIndex
				while let t = pop(kind: .type) {
					try require(paramKind == .closureProp || paramKind == .constantPropKeyPath)
					param.children.insert(t, at: fixedChildrenEndIndex)
				}
				let name = try require(pop(kind: .identifier))
				var text = try require(name.text)
				if paramKind == .constantPropString, !text.isEmpty, text.first == "_" {
					text = String(text.dropFirst())
				}
				param.children.insert(SwiftSymbol(kind: .functionSignatureSpecializationParamPayload, contents: .name(text)), at: fixedChildrenEndIndex)
				spec.children[paramIndexPair.offset] = param
			default: break
			}
		}
		return spec
	}
	
	mutating func demangleFuncSpecParam(kind: SwiftSymbol.Kind) throws -> SwiftSymbol {
		var param = SwiftSymbol(kind: kind)
		switch try scanner.readScalar() {
		case "n": break
		case "c": param.children.append(SwiftSymbol(kind: .functionSignatureSpecializationParamKind, contents: .index(FunctionSigSpecializationParamKind.closureProp.rawValue)))
		case "p":
			switch try scanner.readScalar() {
			case "f": param.children.append(SwiftSymbol(kind: .functionSignatureSpecializationParamKind, contents: .index(FunctionSigSpecializationParamKind.constantPropFunction.rawValue)))
			case "g": param.children.append(SwiftSymbol(kind: .functionSignatureSpecializationParamKind, contents: .index(FunctionSigSpecializationParamKind.constantPropGlobal.rawValue)))
			case "i": param.children.append(SwiftSymbol(kind: .functionSignatureSpecializationParamKind, contents: .index(FunctionSigSpecializationParamKind.constantPropInteger.rawValue)))
			case "d": param.children.append(SwiftSymbol(kind: .functionSignatureSpecializationParamKind, contents: .index(FunctionSigSpecializationParamKind.constantPropFloat.rawValue)))
			case "s":
				let encoding: String
				switch try scanner.readScalar() {
				case "b": encoding = "u8"
				case "w": encoding = "u16"
				case "c": encoding = "objc"
				default: throw failure
				}
				param.children.append(SwiftSymbol(kind: .functionSignatureSpecializationParamKind, contents: .index(FunctionSigSpecializationParamKind.constantPropString.rawValue)))
				param.children.append(SwiftSymbol(kind: .functionSignatureSpecializationParamPayload, contents: .name(encoding)))
			case "k":
				param.children.append(SwiftSymbol(kind: .functionSignatureSpecializationParamKind, contents: .index(FunctionSigSpecializationParamKind.constantPropKeyPath.rawValue)))
			default: throw failure
			}
		case "e":
			var value = FunctionSigSpecializationParamKind.existentialToGeneric.rawValue
			if scanner.conditional(scalar: "D") {
				value |= FunctionSigSpecializationParamKind.dead.rawValue
			}
			if scanner.conditional(scalar: "G") {
				value |= FunctionSigSpecializationParamKind.ownedToGuaranteed.rawValue
			}
			if scanner.conditional(scalar: "O") {
				value |= FunctionSigSpecializationParamKind.guaranteedToOwned.rawValue
			}
			if scanner.conditional(scalar: "X") {
				value |= FunctionSigSpecializationParamKind.sroa.rawValue
			}
			param.children.append(SwiftSymbol(kind: .functionSignatureSpecializationParamKind, contents: .index(value)))
		case "d":
			var value = FunctionSigSpecializationParamKind.dead.rawValue
			if scanner.conditional(scalar: "G") {
				value |= FunctionSigSpecializationParamKind.ownedToGuaranteed.rawValue
			}
			if scanner.conditional(scalar: "O") {
				value |= FunctionSigSpecializationParamKind.guaranteedToOwned.rawValue
			}
			if scanner.conditional(scalar: "X") {
				value |= FunctionSigSpecializationParamKind.sroa.rawValue
			}
			param.children.append(SwiftSymbol(kind: .functionSignatureSpecializationParamKind, contents: .index(value)))
		case "g":
			var value = FunctionSigSpecializationParamKind.ownedToGuaranteed.rawValue
			if scanner.conditional(scalar: "O") {
				value |= FunctionSigSpecializationParamKind.guaranteedToOwned.rawValue
			}
			if scanner.conditional(scalar: "X") {
				value |= FunctionSigSpecializationParamKind.sroa.rawValue
			}
			param.children.append(SwiftSymbol(kind: .functionSignatureSpecializationParamKind, contents: .index(value)))
		case "o":
			var value = FunctionSigSpecializationParamKind.guaranteedToOwned.rawValue
			if scanner.conditional(scalar: "X") {
				value |= FunctionSigSpecializationParamKind.sroa.rawValue
			}
			param.children.append(SwiftSymbol(kind: .functionSignatureSpecializationParamKind, contents: .index(value)))
		case "x":
			param.children.append(SwiftSymbol(kind: .functionSignatureSpecializationParamKind, contents: .index(FunctionSigSpecializationParamKind.sroa.rawValue)))
		case "i":
			param.children.append(SwiftSymbol(kind: .functionSignatureSpecializationParamKind, contents: .index(FunctionSigSpecializationParamKind.boxToValue.rawValue)))
		case "s":
			param.children.append(SwiftSymbol(kind: .functionSignatureSpecializationParamKind, contents: .index(FunctionSigSpecializationParamKind.boxToStack.rawValue)))
		case "r":
			param.children.append(SwiftSymbol(kind: .functionSignatureSpecializationParamKind, contents: .index(FunctionSigSpecializationParamKind.inOutToOut.rawValue)))
		default: throw failure
		}
		return param
	}
	
	mutating func addFuncSpecParamNumber(param: inout SwiftSymbol, kind: FunctionSigSpecializationParamKind) throws {
		param.children.append(SwiftSymbol(kind: .functionSignatureSpecializationParamKind, contents: .index(kind.rawValue)))
		let str = scanner.readWhile { $0.isDigit }
		try require(!str.isEmpty)
		param.children.append(SwiftSymbol(kind: .functionSignatureSpecializationParamPayload, contents: .name(str)))
	}
	
	mutating func demangleSpecAttributes(kind: SwiftSymbol.Kind, demangleUniqueId: Bool = false) throws -> SwiftSymbol {
		let isSerialized = scanner.conditional(scalar: "q")
		let asyncRemoved = scanner.conditional(scalar: "a")
		let passId = try scanner.readScalar().value - UnicodeScalar("0").value
		try require((0...9).contains(passId))
		let contents = demangleUniqueId ? (try demangleNatural().map { SwiftSymbol.Contents.index($0) } ?? SwiftSymbol.Contents.none) : SwiftSymbol.Contents.none
		var specName = SwiftSymbol(kind: kind, contents: contents)
		if isSerialized {
			specName.children.append(SwiftSymbol(kind: .isSerialized))
		}
		if asyncRemoved {
			specName.children.append(SwiftSymbol(kind: .asyncRemoved))
		}
		specName.children.append(SwiftSymbol(kind: .specializationPassID, contents: .index(UInt64(passId))))
		return specName
	}
	
	mutating func demangleWitness() throws -> SwiftSymbol {
		let c = try scanner.readScalar()
		switch c {
		case "C": return SwiftSymbol(kind: .enumCase, child: try require(pop(where: { $0.isEntity })))
		case "V": return SwiftSymbol(kind: .valueWitnessTable, child: try require(pop(kind: .type)))
		case "v":
			let directness: UInt64
			switch try scanner.readScalar() {
			case "d": directness = Directness.direct.rawValue
			case "i": directness = Directness.indirect.rawValue
			default: throw failure
			}
			return SwiftSymbol(kind: .fieldOffset, children: [SwiftSymbol(kind: .directness, contents: .index(directness)), try require(pop(where: { $0.isEntity }))])
		case "S": return SwiftSymbol(kind: .protocolSelfConformanceWitnessTable, child: try popProtocolConformance())
		case "P": return SwiftSymbol(kind: .protocolWitnessTable, child: try popProtocolConformance())
		case "p": return SwiftSymbol(kind: .protocolWitnessTablePattern, child: try popProtocolConformance())
		case "G": return SwiftSymbol(kind: .genericProtocolWitnessTable, child: try popProtocolConformance())
		case "I": return SwiftSymbol(kind: .genericProtocolWitnessTableInstantiationFunction, child: try popProtocolConformance())
		case "r": return SwiftSymbol(kind: .resilientProtocolWitnessTable, child: try popProtocolConformance())
		case "l":
			let conf = try popProtocolConformance()
			let type = try require(pop(kind: .type))
			return SwiftSymbol(kind: .lazyProtocolWitnessTableAccessor, children: [type, conf])
		case "L":
			let conf = try popProtocolConformance()
			let type = try require(pop(kind: .type))
			return SwiftSymbol(kind: .lazyProtocolWitnessTableCacheVariable, children: [type, conf])
		case "a": return SwiftSymbol(kind: .protocolWitnessTableAccessor, child: try popProtocolConformance())
		case "t":
			let name = try require(pop(where: { $0.isDeclName }))
			let conf = try popProtocolConformance()
			return SwiftSymbol(kind: .associatedTypeMetadataAccessor, children: [conf, name])
		case "T":
			let protoType = try require(pop(kind: .type))
			var assocTypePath = SwiftSymbol(kind: .assocTypePath)
			var firstElem = false
			repeat {
				firstElem = pop(kind: .firstElementMarker) != nil
				let assocType = try require(pop(where: { $0.isDeclName }))
				assocTypePath.children.insert(assocType, at: 0)
			} while !firstElem
			return SwiftSymbol(kind: .associatedTypeWitnessTableAccessor, children: [try popProtocolConformance(), assocTypePath, protoType])
		case "b":
			let protoTy = try require(pop(kind: .type))
			let conf = try popProtocolConformance()
			return SwiftSymbol(kind: .baseWitnessTableAccessor, children: [conf, protoTy])
		case "O":
			let sig = pop(kind: .dependentGenericSignature)
			let type = try require(pop(kind: .type))
			let children: [SwiftSymbol] = sig.map { [type, $0] } ?? [type]
			switch try scanner.readScalar() {
			case "C": return SwiftSymbol(kind: .outlinedInitializeWithCopyNoValueWitness, children: children)
			case "D": return SwiftSymbol(kind: .outlinedAssignWithTakeNoValueWitness, children: children)
			case "F": return SwiftSymbol(kind: .outlinedAssignWithCopyNoValueWitness, children: children)
			case "H": return SwiftSymbol(kind: .outlinedDestroyNoValueWitness, children: children)
			case "y": return SwiftSymbol(kind: .outlinedCopy, children: children)
			case "e": return SwiftSymbol(kind: .outlinedConsume, children: children)
			case "r": return SwiftSymbol(kind: .outlinedRetain, children: children)
			case "s": return SwiftSymbol(kind: .outlinedRelease, children: children)
			case "b": return SwiftSymbol(kind: .outlinedInitializeWithTake, children: children)
			case "c": return SwiftSymbol(kind: .outlinedInitializeWithCopy, children: children)
			case "d": return SwiftSymbol(kind: .outlinedAssignWithTake, children: children)
			case "f": return SwiftSymbol(kind: .outlinedAssignWithCopy, children: children)
			case "h": return SwiftSymbol(kind: .outlinedDestroy, children: children)
			case "g": return SwiftSymbol(kind: .outlinedEnumGetTag, children: children)
			case "i": return SwiftSymbol(kind: .outlinedEnumTagStore, children: children)
			case "j": return SwiftSymbol(kind: .outlinedEnumProjectDataForLoad, children: children)
			default: throw failure
			}
		case "Z", "z":
			var declList = SwiftSymbol(kind: .globalVariableOnceDeclList)
			while pop(kind: .firstElementMarker) != nil {
				guard let identifier = pop(where: { $0.isDeclName }) else { throw failure }
				declList.children.append(identifier)
			}
			declList.children.reverse()
			return SwiftSymbol(kind: c == "Z" ? .globalVariableOnceFunction : .globalVariableOnceToken, children: [try popContext(), declList])
		case "J":
			return try demangleDifferentiabilityWitness()
		default: throw failure
		}
	}
	
	mutating func demangleSpecialType() throws -> SwiftSymbol {
		let specialChar = try scanner.readScalar()
		switch specialChar {
		case "E": return try popFunctionType(kind: .noEscapeFunctionType)
		case "A": return try popFunctionType(kind: .escapingAutoClosureType)
		case "f": return try popFunctionType(kind: .thinFunctionType)
		case "K": return try popFunctionType(kind: .autoClosureType)
		case "U": return try popFunctionType(kind: .uncurriedFunctionType)
		case "L": return try popFunctionType(kind: .escapingObjCBlock)
		case "B": return try popFunctionType(kind: .objCBlock)
		case "C": return try popFunctionType(kind: .cFunctionPointer)
		case "g": fallthrough
		case "G": return try demangleExtendedExistentialShape(nodeKind: specialChar)
		case "j": return try demangleSymbolicExtendedExistentialType()
		case "z":
			switch try scanner.readScalar() {
			case "B": return try popFunctionType(kind: .objCBlock, hasClangType: true)
			case "C": return try popFunctionType(kind: .cFunctionPointer, hasClangType: true)
			default: throw failure
			}
		case "o": return SwiftSymbol(typeWithChildKind: .unowned, childChild: try require(pop(kind: .type)))
		case "u": return SwiftSymbol(typeWithChildKind: .unmanaged, childChild: try require(pop(kind: .type)))
		case "w": return SwiftSymbol(typeWithChildKind: .weak, childChild: try require(pop(kind: .type)))
		case "b": return SwiftSymbol(typeWithChildKind: .silBoxType, childChild: try require(pop(kind: .type)))
		case "D": return SwiftSymbol(typeWithChildKind: .dynamicSelf, childChild: try require(pop(kind: .type)))
		case "M":
			let mtr = try demangleMetatypeRepresentation()
			let type = try require(pop(kind: .type))
			return SwiftSymbol(typeWithChildKind: .metatype, childChildren: [mtr, type])
		case "m":
			let mtr = try demangleMetatypeRepresentation()
			let type = try require(pop(kind: .type))
			return SwiftSymbol(typeWithChildKind: .existentialMetatype, childChildren: [mtr, type])
		case "P":
			let reqs = try demangleConstrainedExistentialRequirementList()
			let base = try require(pop(kind: .type))
			return SwiftSymbol(typeWithChildKind: .constrainedExistential, childChildren: [base, reqs])
		case "p": return SwiftSymbol(typeWithChildKind: .existentialMetatype, childChild: try require(pop(kind: .type)))
		case "c":
			let superclass = try require(pop(kind: .type))
			let protocols = try demangleProtocolList()
			return SwiftSymbol(typeWithChildKind: .protocolListWithClass, childChildren: [protocols, superclass])
		case "l": return SwiftSymbol(typeWithChildKind: .protocolListWithAnyObject, childChild: try demangleProtocolList())
		case "X", "x":
			var signatureGenericArgs: (SwiftSymbol, SwiftSymbol)? = nil
			if specialChar == "X" {
				signatureGenericArgs = (try require(pop(kind: .dependentGenericSignature)), try popTypeList())
			}
			
			let fieldTypes = try popTypeList()
			var layout = SwiftSymbol(kind: .silBoxLayout)
			for fieldType in fieldTypes.children {
				try require(fieldType.kind == .type)
				if fieldType.children.first?.kind == .inOut {
					layout.children.append(SwiftSymbol(kind: .silBoxMutableField, child: SwiftSymbol(kind: .type, child: try require(fieldType.children.first?.children.first))))
				} else {
					layout.children.append(SwiftSymbol(kind: .silBoxImmutableField, child: fieldType))
				}
			}
			var boxType = SwiftSymbol(kind: .silBoxTypeWithLayout, child: layout)
			if let (signature, genericArgs) = signatureGenericArgs {
				boxType.children.append(signature)
				boxType.children.append(genericArgs)
			}
			return SwiftSymbol(kind: .type, child: boxType)
		case "Y": return try demangleAnyGenericType(kind: .otherNominalType)
		case "Z":
			let types = try popTypeList()
			let name = try require(pop(kind: .identifier))
			let parent = try popContext()
			return SwiftSymbol(kind: .anonymousContext, children: [name, parent, types])
		case "e": return SwiftSymbol(kind: .type, child: SwiftSymbol(kind: .errorType))
		case "S":
			switch try scanner.readScalar() {
			case "q": return SwiftSymbol(kind: .type, child: SwiftSymbol(kind: .sugaredOptional))
			case "a": return SwiftSymbol(kind: .type, child: SwiftSymbol(kind: .sugaredArray))
			case "D": return SwiftSymbol(kind: .type, child: SwiftSymbol(kind: .sugaredDictionary))
			case "p": return SwiftSymbol(kind: .type, child: SwiftSymbol(kind: .sugaredParen))
			default: throw failure
			}
		default: throw failure
		}
	}
	
	mutating func demangleSymbolicExtendedExistentialType() throws -> SwiftSymbol {
		let retroactiveConformances = try popRetroactiveConformances()
		var args = SwiftSymbol(kind: .typeList)
		while let type = pop(kind: .type) {
			args.children.append(type)
		}
		args.children.reverse()
		let shape = try require(pop(where: { $0 == .uniqueExtendedExistentialTypeShapeSymbolicReference || $0 == .nonUniqueExtendedExistentialTypeShapeSymbolicReference }))
		if let retroactiveConformances {
			return SwiftSymbol(typeWithChildKind: .symbolicExtendedExistentialType, childChildren: [shape, args, retroactiveConformances])
		} else {
			return SwiftSymbol(typeWithChildKind: .symbolicExtendedExistentialType, childChildren: [shape, args])
		}
	}
	
	mutating func demangleExtendedExistentialShape(nodeKind: UnicodeScalar) throws -> SwiftSymbol {
		let type = try require(pop(kind: .type))
		var genSig: SwiftSymbol?
		if nodeKind == "G" {
			genSig = pop(kind: .dependentGenericSignature)
		}
		if let genSig {
			return SwiftSymbol(kind: .extendedExistentialTypeShape, children: [genSig, type])
		} else {
			return SwiftSymbol(kind: .extendedExistentialTypeShape, child: type)
		}
	}
	
	mutating func demangleMetatypeRepresentation() throws -> SwiftSymbol {
		let value: String
		switch try scanner.readScalar() {
		case "t": value = "@thin"
		case "T": value = "@thick"
		case "o": value = "@objc_metatype"
		default: throw failure
		}
		return SwiftSymbol(kind: .metatypeRepresentation, contents: .name(value))
	}
	
	mutating func demangleAccessor(child: SwiftSymbol) throws -> SwiftSymbol {
		let kind: SwiftSymbol.Kind
		switch try scanner.readScalar() {
		case "m": kind = .materializeForSet
		case "s": kind = .setter
		case "g": kind = .getter
		case "G": kind = .globalGetter
		case "w": kind = .willSet
		case "W": kind = .didSet
		case "r": kind = .readAccessor
		case "y": kind = .read2Accessor
		case "M": kind = .modifyAccessor
		case "x": kind = .modify2Accessor
		case "i": kind = .initAccessor
		case "a":
			switch try scanner.readScalar() {
			case "O": kind = .owningMutableAddressor
			case "o": kind = .nativeOwningMutableAddressor
			case "p": kind = .nativePinningMutableAddressor
			case "u": kind = .unsafeMutableAddressor
			default: throw failure
			}
		case "l":
			switch try scanner.readScalar() {
			case "O": kind = .owningAddressor
			case "o": kind = .nativeOwningAddressor
			case "p": kind = .nativePinningAddressor
			case "u": kind = .unsafeAddressor
			default: throw failure
			}
		case "p": return child
		default: throw failure
		}
		return SwiftSymbol(kind: kind, child: child)
	}
	
	mutating func demangleFunctionEntity() throws -> SwiftSymbol {
		let argsAndKind: (args: DemangleFunctionEntityArgs, kind: SwiftSymbol.Kind)
		switch try scanner.readScalar() {
		case "D": argsAndKind = (.none, .deallocator)
		case "d": argsAndKind = (.none, .destructor)
		case "Z": argsAndKind = (.none, .isolatedDeallocator)
		case "E": argsAndKind = (.none, .iVarDestroyer)
		case "e": argsAndKind = (.none, .iVarInitializer)
		case "i": argsAndKind = (.none, .initializer)
		case "C": argsAndKind = (.typeAndMaybePrivateName, .allocator)
		case "c": argsAndKind = (.typeAndMaybePrivateName, .constructor)
		case "U": argsAndKind = (.typeAndIndex, .explicitClosure)
		case "u": argsAndKind = (.typeAndIndex, .implicitClosure)
		case "A": argsAndKind = (.index, .defaultArgumentInitializer)
		case "m": return try demangleEntity(kind: .macro)
		case "M": return try demangleMacroExpansion()
		case "p": return try demangleEntity(kind: .genericTypeParamDecl)
		case "P": argsAndKind = (.none, .propertyWrapperBackingInitializer)
		case "W": argsAndKind = (.none, .propertyWrapperInitFromProjectedValue)
		default: throw failure
		}
		
		var children = [SwiftSymbol]()
		switch argsAndKind.args {
		case .none: break
		case .index: children.append(try demangleIndexAsName())
		case .typeAndIndex:
			let index = try demangleIndexAsName()
			let type = try require(pop(kind: .type))
			children += [index, type]
		case .typeAndMaybePrivateName:
			let privateName = pop(kind: .privateDeclName)
			let paramType = try require(pop(kind: .type))
			let labelList = try popFunctionParamLabels(type: paramType)
			if let ll = labelList {
				children.append(ll)
				children.append(paramType)
			} else {
				children.append(paramType)
			}
			if let pn = privateName {
				children.append(pn)
			}
		}
		return SwiftSymbol(kind: argsAndKind.kind, children: [try popContext()] + children)
	}
	
	mutating func demangleEntity(kind: SwiftSymbol.Kind) throws -> SwiftSymbol {
		var type = try require(pop(kind: .type))
		let labelList = try popFunctionParamLabels(type: type)
		let name = try require(pop(where: { $0.isDeclName }))
		let context = try popContext()
		let result = if let labelList = labelList {
			SwiftSymbol(kind: kind, children: [context, name, labelList, type])
		} else {
			SwiftSymbol(kind: kind, children: [context, name, type])
		}
		setParentForOpaqueReturnTypeNodes(visited: &type, parentId: getParentId(parent: result, flavor: flavor))
		return result
	}
	
	mutating func demangleVariable() throws -> SwiftSymbol {
		return try demangleAccessor(child: demangleEntity(kind: .variable))
	}
	
	mutating func demangleSubscript() throws -> SwiftSymbol {
		let privateName = pop(kind: .privateDeclName)
		var type = try require(pop(kind: .type))
		let labelList = try popFunctionParamLabels(type: type)
		let context = try popContext()
		
		var ss = SwiftSymbol(kind: .subscript, child: context)
		if let labelList = labelList {
			ss.children.append(labelList)
		}
		setParentForOpaqueReturnTypeNodes(visited: &type, parentId: getParentId(parent: ss, flavor: flavor))
		ss.children.append(type)
		if let pn = privateName {
			ss.children.append(pn)
		}
		return try demangleAccessor(child: ss)
	}
	
	mutating func demangleProtocolList() throws -> SwiftSymbol {
		var typeList = SwiftSymbol(kind: .typeList)
		if pop(kind: .emptyList) == nil {
			var firstElem = false
			repeat {
				firstElem = pop(kind: .firstElementMarker) != nil
				typeList.children.insert(try popProtocol(), at: 0)
			} while !firstElem
		}
		return SwiftSymbol(kind: .protocolList, child: typeList)
	}
	
	mutating func demangleProtocolListType() throws -> SwiftSymbol {
		return SwiftSymbol(kind: .type, child: try demangleProtocolList())
	}
	
	mutating func demangleConstrainedExistentialRequirementList() throws -> SwiftSymbol {
		var reqList = SwiftSymbol(kind: .constrainedExistentialRequirementList)
		var firstElement = false
		repeat {
			firstElement = (pop(kind: .firstElementMarker) != nil)
			let req = try require(pop(where: { $0.isRequirement }))
			reqList.children.append(req)
		} while !firstElement
		reqList.children.reverse()
		return reqList
	}
	
	mutating func demangleGenericSignature(hasParamCounts: Bool) throws -> SwiftSymbol {
		var sig = SwiftSymbol(kind: .dependentGenericSignature)
		if hasParamCounts {
			while !scanner.conditional(scalar: "l") {
				var count: UInt64 = 0
				if !scanner.conditional(scalar: "z") {
					count = try demangleIndex() + 1
				}
				sig.children.append(SwiftSymbol(kind: .dependentGenericParamCount, contents: .index(count)))
			}
		} else {
			sig.children.append(SwiftSymbol(kind: .dependentGenericParamCount, contents: .index(1)))
		}
		let requirementsIndex = sig.children.endIndex
		while let req = pop(where: { $0.isRequirement }) {
			sig.children.insert(req, at: requirementsIndex)
		}
		return sig
	}
	
	mutating func demangleGenericRequirement() throws -> SwiftSymbol {
		let constraintAndTypeKinds: (constraint: DemangleGenericRequirementConstraintKind, type: DemangleGenericRequirementTypeKind)
		var inverseKind: SwiftSymbol?
		switch try scanner.readScalar() {
		case "V": constraintAndTypeKinds = (.valueMarker, .generic)
		case "v": constraintAndTypeKinds = (.packMarker, .generic)
		case "c": constraintAndTypeKinds = (.baseClass, .assoc)
		case "C": constraintAndTypeKinds = (.baseClass, .compoundAssoc)
		case "b": constraintAndTypeKinds = (.baseClass, .generic)
		case "B": constraintAndTypeKinds = (.baseClass, .substitution)
		case "t": constraintAndTypeKinds = (.sameType, .assoc)
		case "T": constraintAndTypeKinds = (.sameType, .compoundAssoc)
		case "s": constraintAndTypeKinds = (.sameType, .generic)
		case "S": constraintAndTypeKinds = (.sameType, .substitution)
		case "m": constraintAndTypeKinds = (.layout, .assoc)
		case "M": constraintAndTypeKinds = (.layout, .compoundAssoc)
		case "l": constraintAndTypeKinds = (.layout, .generic)
		case "L": constraintAndTypeKinds = (.layout, .substitution)
		case "p": constraintAndTypeKinds = (.protocol, .assoc)
		case "P": constraintAndTypeKinds = (.protocol, .compoundAssoc)
		case "Q": constraintAndTypeKinds = (.protocol, .substitution)
		case "h": constraintAndTypeKinds = (.sameShape, .generic)
		case "i":
			constraintAndTypeKinds = (.inverse, .generic)
			inverseKind = try demangleIndexAsName()
		case "I":
			constraintAndTypeKinds = (.inverse, .substitution)
			inverseKind = try demangleIndexAsName()
		default:
			constraintAndTypeKinds = (.protocol, .generic)
			try scanner.backtrack()
		}
		
		let constrType: SwiftSymbol
		switch constraintAndTypeKinds.type {
		case .generic: constrType = SwiftSymbol(kind: .type, child: try demangleGenericParamIndex())
		case .assoc:
			constrType = try demangleAssociatedTypeSimple(index: demangleGenericParamIndex())
			substitutions.append(constrType)
		case .compoundAssoc:
			constrType = try demangleAssociatedTypeCompound(index: try demangleGenericParamIndex())
			substitutions.append(constrType)
		case .substitution: constrType = try require(pop(kind: .type))
		}
		
		switch constraintAndTypeKinds.constraint {
		case .valueMarker: return SwiftSymbol(kind: .dependentGenericParamPackMarker, children: [constrType, try require(pop(kind: .type))])
		case .packMarker: return SwiftSymbol(kind: .dependentGenericParamPackMarker, children: [constrType])
		case .protocol: return SwiftSymbol(kind: .dependentGenericConformanceRequirement, children: [constrType, try popProtocol()])
		case .inverse: return SwiftSymbol(kind: .dependentGenericInverseConformanceRequirement, children: [constrType, try require(inverseKind)])
		case .baseClass: return SwiftSymbol(kind: .dependentGenericConformanceRequirement, children: [constrType, try require(pop(kind: .type))])
		case .sameType: return SwiftSymbol(kind: .dependentGenericSameTypeRequirement, children: [constrType, try require(pop(kind: .type))])
		case .sameShape: return SwiftSymbol(kind: .dependentGenericSameShapeRequirement, children: [constrType, try require(pop(kind: .type))])
		case .layout:
			let c = try scanner.readScalar()
			var size: SwiftSymbol? = nil
			var alignment: SwiftSymbol? = nil
			switch c {
			case "U", "R", "N", "C", "D", "T": break
			case "E", "M":
				size = try demangleIndexAsName()
				alignment = try demangleIndexAsName()
			case "e", "m":
				size = try demangleIndexAsName()
			default: throw failure
			}
			let name = SwiftSymbol(kind: .identifier, contents: .name(String(String.UnicodeScalarView([c]))))
			var layoutRequirement = SwiftSymbol(kind: .dependentGenericLayoutRequirement, children: [constrType, name])
			if let s = size {
				layoutRequirement.children.append(s)
			}
			if let a = alignment {
				layoutRequirement.children.append(a)
			}
			return layoutRequirement
		}
	}
	
	mutating func demangleGenericType() throws -> SwiftSymbol {
		let genSig = try require(pop(kind: .dependentGenericSignature))
		let type = try require(pop(kind: .type))
		return SwiftSymbol(typeWithChildKind: .dependentGenericType, childChildren: [genSig, type])
	}
	
	mutating func demangleValueWitness() throws -> SwiftSymbol {
		let code = try scanner.readScalars(count: 2)
		let kind = try require(ValueWitnessKind(code: code))
		return SwiftSymbol(kind: .valueWitness, children: [try require(pop(kind: .type))], contents: .index(kind.rawValue))
	}
}

fileprivate extension SwiftSymbol.Kind {
	var isMacroExpansion: Bool {
		switch self {
		case .accessorAttachedMacroExpansion: return true
		case .memberAttributeAttachedMacroExpansion: return true
		case .freestandingMacroExpansion: return true
		case .memberAttachedMacroExpansion: return true
		case .peerAttachedMacroExpansion: return true
		case .conformanceAttachedMacroExpansion: return true
		case .extensionAttachedMacroExpansion: return true
		case .macroExpansionLoc: return true
		default: return false
		}
	}
}

fileprivate extension Demangler {
	mutating func demangleMacroExpansion() throws -> SwiftSymbol {
		let kind: SwiftSymbol.Kind
		let isAttached: Bool
		let isFreestanding: Bool
		switch try scanner.readScalar() {
		case "a": (kind, isAttached, isFreestanding) = (.accessorAttachedMacroExpansion, true, false)
		case "r": (kind, isAttached, isFreestanding) = (.memberAttributeAttachedMacroExpansion, true, false)
		case "m": (kind, isAttached, isFreestanding) = (.memberAttachedMacroExpansion, true, false)
		case "p": (kind, isAttached, isFreestanding) = (.peerAttachedMacroExpansion, true, false)
		case "c": (kind, isAttached, isFreestanding) = (.conformanceAttachedMacroExpansion, true, false)
		case "b": (kind, isAttached, isFreestanding) = (.bodyAttachedMacroExpansion, true, false)
		case "f": (kind, isAttached, isFreestanding) = (.freestandingMacroExpansion, false, true)
		case "u": (kind, isAttached, isFreestanding) = (.macroExpansionUniqueName, false, false)
		case "X":
			let line = try demangleIndex()
			let col = try demangleIndex()
			let lineNode = SwiftSymbol(kind: .index, contents: .index(line))
			let colNode = SwiftSymbol(kind: .index, contents: .index(col))
			let buffer = try require(pop(kind: .identifier))
			let module = try require(pop(kind: .identifier))
			return SwiftSymbol(kind: .macroExpansionLoc, children: [module, buffer, lineNode, colNode])
		default:
			throw failure
		}
		
		let macroName = try require(pop(kind: .identifier))
		let privateDiscriminator = isFreestanding ? pop(kind: .privateDeclName) : nil
		let attachedName = isAttached ? pop(where: { $0.isDeclName }) : nil
		let context = try pop(where: { $0.isMacroExpansion }) ?? popContext()
		let discriminator = try demangleIndexAsName()
		var result: SwiftSymbol
		if isAttached {
			result = SwiftSymbol(kind: kind, children: [context, try require(attachedName), macroName, discriminator])
		} else {
			result = SwiftSymbol(kind: kind, children: [context, macroName, discriminator])
		}
		if let privateDiscriminator {
			result.children.append(privateDiscriminator)
		}
		return result
	}
	
	mutating func demangleIntegerType() throws -> SwiftSymbol {
		if scanner.conditional(scalar: "n") {
			return SwiftSymbol(kind: .type, children: [SwiftSymbol(kind: .negativeInteger, contents: .index(try demangleIndex()))])
		} else {
			return SwiftSymbol(kind: .type, children: [SwiftSymbol(kind: .integer, contents: .index(try demangleIndex()))])
		}
	}
	
	mutating func demangleObjCTypeName() throws -> SwiftSymbol {
		var type = SwiftSymbol(kind: .type)
		if scanner.conditional(scalar: "C") {
			let module: SwiftSymbol
			if scanner.conditional(scalar: "s") {
				module = SwiftSymbol(kind: .module, contents: .name(stdlibName))
			} else {
				module = try demangleIdentifier().changeKind(.module)
			}
			type.children.append(SwiftSymbol(kind: .class, children: [module, try demangleIdentifier()]))
		} else if scanner.conditional(scalar: "P") {
			let module: SwiftSymbol
			if scanner.conditional(scalar: "s") {
				module = SwiftSymbol(kind: .module, contents: .name(stdlibName))
			} else {
				module = try demangleIdentifier().changeKind(.module)
			}
			type.children.append(SwiftSymbol(kind: .protocolList, child: SwiftSymbol(kind: .typeList, child: SwiftSymbol(kind: .type, child: SwiftSymbol(kind: .protocol, children: [module, try demangleIdentifier()])))))
			try scanner.match(scalar: "_")
		} else {
			throw failure
		}
		try require(scanner.isAtEnd)
		return SwiftSymbol(kind: .global, child: SwiftSymbol(kind: .typeMangling, child: type))
	}
}

// MARK Demangle.cpp (Swift 3)

fileprivate extension Demangler {
	
	mutating func demangleSwift3TopLevelSymbol() throws -> SwiftSymbol {
		reset()
		
		try scanner.match(string: "_T")
		var children = [SwiftSymbol]()
		
		switch (try scanner.readScalar(), try scanner.readScalar()) {
		case ("T", "S"):
			repeat {
				children.append(try demangleSwift3SpecializedAttribute())
				nameStack.removeAll()
			} while scanner.conditional(string: "_TTS")
			try scanner.match(string: "_T")
		case ("T", "o"): children.append(SwiftSymbol(kind: .objCAttribute))
		case ("T", "O"): children.append(SwiftSymbol(kind: .nonObjCAttribute))
		case ("T", "D"): children.append(SwiftSymbol(kind: .dynamicAttribute))
		case ("T", "d"): children.append(SwiftSymbol(kind: .directMethodReferenceAttribute))
		case ("T", "v"): children.append(SwiftSymbol(kind: .vTableAttribute))
		default: try scanner.backtrack(count: 2)
		}
		
		children.append(try demangleSwift3Global())
		
		let remainder = scanner.remainder()
		if !remainder.isEmpty {
			children.append(SwiftSymbol(kind: .suffix, contents: .name(remainder)))
		}
		
		return SwiftSymbol(kind: .global, children: children)
	}
	
	mutating func demangleSwift3Global() throws -> SwiftSymbol {
		let c1 = try scanner.readScalar()
		let c2 = try scanner.readScalar()
		switch (c1, c2) {
		case ("M", "P"): return SwiftSymbol(kind: .genericTypeMetadataPattern, children: [try demangleSwift3Type()])
		case ("M", "a"): return SwiftSymbol(kind: .typeMetadataAccessFunction, children: [try demangleSwift3Type()])
		case ("M", "L"): return SwiftSymbol(kind: .typeMetadataLazyCache, children: [try demangleSwift3Type()])
		case ("M", "m"): return SwiftSymbol(kind: .metaclass, children: [try demangleSwift3Type()])
		case ("M", "n"): return SwiftSymbol(kind: .nominalTypeDescriptor, children: [try demangleSwift3Type()])
		case ("M", "f"): return SwiftSymbol(kind: .fullTypeMetadata, children: [try demangleSwift3Type()])
		case ("M", "p"): return SwiftSymbol(kind: .protocolDescriptor, children: [try demangleSwift3ProtocolName()])
		case ("M", _):
			try scanner.backtrack()
			return SwiftSymbol(kind: .typeMetadata, children: [try demangleSwift3Type()])
		case ("P", "A"):
			return SwiftSymbol(kind: scanner.conditional(scalar: "o") ? .partialApplyObjCForwarder : .partialApplyForwarder, children: scanner.conditional(string: "__T") ? [try demangleSwift3Global()] : [])
		case ("P", _): throw scanner.unexpectedError()
		case ("t", _):
			try scanner.backtrack()
			return SwiftSymbol(kind: .typeMangling, children: [try demangleSwift3Type()])
		case ("w", _):
			let c3 = try scanner.readScalar()
			let value: UInt64
			switch (c2, c3) {
			case ("a", "l"): value = ValueWitnessKind.allocateBuffer.rawValue
			case ("c", "a"): value = ValueWitnessKind.assignWithCopy.rawValue
			case ("t", "a"): value = ValueWitnessKind.assignWithTake.rawValue
			case ("d", "e"): value = ValueWitnessKind.deallocateBuffer.rawValue
			case ("x", "x"): value = ValueWitnessKind.destroy.rawValue
			case ("X", "X"): value = ValueWitnessKind.destroyBuffer.rawValue
			case ("C", "P"): value = ValueWitnessKind.initializeBufferWithCopyOfBuffer.rawValue
			case ("C", "p"): value = ValueWitnessKind.initializeBufferWithCopy.rawValue
			case ("c", "p"): value = ValueWitnessKind.initializeWithCopy.rawValue
			case ("C", "c"): value = ValueWitnessKind.initializeArrayWithCopy.rawValue
			case ("T", "K"): value = ValueWitnessKind.initializeBufferWithTakeOfBuffer.rawValue
			case ("T", "k"): value = ValueWitnessKind.initializeBufferWithTake.rawValue
			case ("t", "k"): value = ValueWitnessKind.initializeWithTake.rawValue
			case ("T", "t"): value = ValueWitnessKind.initializeArrayWithTakeFrontToBack.rawValue
			case ("t", "T"): value = ValueWitnessKind.initializeArrayWithTakeBackToFront.rawValue
			case ("p", "r"): value = ValueWitnessKind.projectBuffer.rawValue
			case ("X", "x"): value = ValueWitnessKind.destroyArray.rawValue
			case ("x", "s"): value = ValueWitnessKind.storeExtraInhabitant.rawValue
			case ("x", "g"): value = ValueWitnessKind.getExtraInhabitantIndex.rawValue
			case ("u", "g"): value = ValueWitnessKind.getEnumTag.rawValue
			case ("u", "p"): value = ValueWitnessKind.destructiveProjectEnumData.rawValue
			default: throw scanner.unexpectedError()
			}
			return SwiftSymbol(kind: .valueWitness, children: [try demangleSwift3Type()], contents: .index(value))
		case ("W", "V"): return SwiftSymbol(kind: .valueWitnessTable, children: [try demangleSwift3Type()])
		case ("W", "v"): return SwiftSymbol(kind: .fieldOffset, children: [SwiftSymbol(kind: .directness, contents: .index(try scanner.readScalar() == "d" ? 0 : 1)), try demangleSwift3Entity()])
		case ("W", "P"): return SwiftSymbol(kind: .protocolWitnessTable, children: [try demangleSwift3ProtocolConformance()])
		case ("W", "G"): return SwiftSymbol(kind: .genericProtocolWitnessTable, children: [try demangleSwift3ProtocolConformance()])
		case ("W", "I"): return SwiftSymbol(kind: .genericProtocolWitnessTableInstantiationFunction, children: [try demangleSwift3ProtocolConformance()])
		case ("W", "l"): return SwiftSymbol(kind: .lazyProtocolWitnessTableAccessor, children: [try demangleSwift3Type(), try demangleSwift3ProtocolConformance()])
		case ("W", "L"): return SwiftSymbol(kind: .lazyProtocolWitnessTableCacheVariable, children: [try demangleSwift3Type(), try demangleSwift3ProtocolConformance()])
		case ("W", "a"): return SwiftSymbol(kind: .protocolWitnessTableAccessor, children: [try demangleSwift3ProtocolConformance()])
		case ("W", "t"): return SwiftSymbol(kind: .associatedTypeMetadataAccessor, children: [try demangleSwift3ProtocolConformance(), try demangleSwift3DeclName()])
		case ("W", "T"): return SwiftSymbol(kind: .associatedTypeWitnessTableAccessor, children: [try demangleSwift3ProtocolConformance(), try demangleSwift3DeclName(), try demangleSwift3ProtocolName()])
		case ("W", _): throw scanner.unexpectedError()
		case ("T","W"): return SwiftSymbol(kind: .protocolWitness, children: [try demangleSwift3ProtocolConformance(), try demangleSwift3Entity()])
		case ("T", "R"): fallthrough
		case ("T", "r"): return SwiftSymbol(kind: c2 == "R" ? SwiftSymbol.Kind.reabstractionThunkHelper : SwiftSymbol.Kind.reabstractionThunk, children: scanner.conditional(scalar: "G") ? [try demangleSwift3GenericSignature(), try demangleSwift3Type(), try demangleSwift3Type()] : [try demangleSwift3Type(), try demangleSwift3Type()])
		default:
			try scanner.backtrack(count: 2)
			return try demangleSwift3Entity()
		}
	}
	
	mutating func demangleSwift3SpecializedAttribute() throws -> SwiftSymbol {
		let c = try scanner.readScalar()
		var children = [SwiftSymbol]()
		if scanner.conditional(scalar: "q") {
			children.append(SwiftSymbol(kind: .isSerialized))
		}
		children.append(SwiftSymbol(kind: .specializationPassID, contents: .index(UInt64(try scanner.readScalar().value - 48))))
		switch c {
		case "r": fallthrough
		case "g":
			while !scanner.conditional(scalar: "_") {
				var parameterChildren = [SwiftSymbol]()
				parameterChildren.append(try demangleSwift3Type())
				while !scanner.conditional(scalar: "_") {
					parameterChildren.append(try demangleSwift3ProtocolConformance())
				}
				children.append(SwiftSymbol(kind: .genericSpecializationParam, children: parameterChildren))
			}
			return SwiftSymbol(kind: c == "r" ? .genericSpecializationNotReAbstracted : .genericSpecialization, children: children)
		case "f":
			var count: UInt64 = 0
			while !scanner.conditional(scalar: "_") {
				var paramChildren = [SwiftSymbol]()
				let c = try scanner.readScalar()
				switch (c, try scanner.readScalar()) {
				case ("n", "_"): break
				case ("c", "p"): paramChildren.append(contentsOf: try demangleSwift3FuncSigSpecializationConstantProp())
				case ("c", "l"):
					paramChildren.append(SwiftSymbol(kind: .functionSignatureSpecializationParamKind, contents: .index(FunctionSigSpecializationParamKind.closureProp.rawValue)))
					paramChildren.append(SwiftSymbol(kind: .functionSignatureSpecializationParamPayload, contents: try demangleSwift3Identifier().contents))
					while !scanner.conditional(scalar: "_") {
						paramChildren.append(try demangleSwift3Type())
					}
				case ("i", "_"): fallthrough
				case ("k", "_"): paramChildren.append(SwiftSymbol(kind: .functionSignatureSpecializationParamKind, contents: .index(c == "i" ? FunctionSigSpecializationParamKind.boxToValue.rawValue : FunctionSigSpecializationParamKind.boxToStack.rawValue)))
				default:
					try scanner.backtrack(count: 2)
					var value: UInt64 = 0
					value |= scanner.conditional(scalar: "d") ? FunctionSigSpecializationParamKind.dead.rawValue : 0
					value |= scanner.conditional(scalar: "g") ? FunctionSigSpecializationParamKind.ownedToGuaranteed.rawValue : 0
					value |= scanner.conditional(scalar: "o") ? FunctionSigSpecializationParamKind.guaranteedToOwned.rawValue : 0
					value |= scanner.conditional(scalar: "s") ? FunctionSigSpecializationParamKind.sroa.rawValue : 0
					try scanner.match(scalar: "_")
					paramChildren.append(SwiftSymbol(kind: .functionSignatureSpecializationParamKind, contents: .index(value)))
				}
				children.append(SwiftSymbol(kind: .functionSignatureSpecializationParam, children: paramChildren, contents: .index(count)))
				count += 1
			}
			return SwiftSymbol(kind: .functionSignatureSpecialization, children: children)
		default: throw scanner.unexpectedError()
		}
	}
	
	mutating func demangleSwift3FuncSigSpecializationConstantProp() throws -> [SwiftSymbol] {
		switch (try scanner.readScalar(), try scanner.readScalar()) {
		case ("f", "r"):
			let name = SwiftSymbol(kind: .functionSignatureSpecializationParamPayload, contents: try demangleSwift3Identifier().contents)
			try scanner.match(scalar: "_")
			let kind = SwiftSymbol(kind: .functionSignatureSpecializationParamKind, contents: .index(FunctionSigSpecializationParamKind.constantPropFunction.rawValue))
			return [kind, name]
		case ("g", _):
			try scanner.backtrack()
			let name = SwiftSymbol(kind: .functionSignatureSpecializationParamPayload, contents: try demangleSwift3Identifier().contents)
			try scanner.match(scalar: "_")
			let kind = SwiftSymbol(kind: .functionSignatureSpecializationParamKind, contents: .index(FunctionSigSpecializationParamKind.constantPropGlobal.rawValue))
			return [kind, name]
		case ("i", _):
			try scanner.backtrack()
			let string = try scanner.readUntil(scalar: "_")
			try scanner.match(scalar: "_")
			let name = SwiftSymbol(kind: .functionSignatureSpecializationParamPayload, contents: .name(string))
			let kind = SwiftSymbol(kind: .functionSignatureSpecializationParamKind, contents: .index(FunctionSigSpecializationParamKind.constantPropInteger.rawValue))
			return [kind, name]
		case ("f", "l"):
			let string = try scanner.readUntil(scalar: "_")
			try scanner.match(scalar: "_")
			let name = SwiftSymbol(kind: .functionSignatureSpecializationParamPayload, contents: .name(string))
			let kind = SwiftSymbol(kind: .functionSignatureSpecializationParamKind, contents: .index(FunctionSigSpecializationParamKind.constantPropFloat.rawValue))
			return [kind, name]
		case ("s", "e"):
			var string: String
			switch try scanner.readScalar() {
			case "0": string = "u8"
			case "1": string = "u16"
			default: throw scanner.unexpectedError()
			}
			try scanner.match(scalar: "v")
			let name = SwiftSymbol(kind: .functionSignatureSpecializationParamPayload, contents: try demangleSwift3Identifier().contents)
			let encoding = SwiftSymbol(kind: .functionSignatureSpecializationParamPayload, contents: .name(string))
			let kind = SwiftSymbol(kind: .functionSignatureSpecializationParamKind, contents: .index(FunctionSigSpecializationParamKind.constantPropString.rawValue))
			try scanner.match(scalar: "_")
			return [kind, encoding, name]
		default: throw scanner.unexpectedError()
		}
	}
	
	
	mutating func demangleSwift3ProtocolConformance() throws -> SwiftSymbol {
		let type = try demangleSwift3Type()
		let prot = try demangleSwift3ProtocolName()
		let context = try demangleSwift3Context()
		return SwiftSymbol(kind: .protocolConformance, children: [type, prot, context])
	}
	
	mutating func demangleSwift3ProtocolName() throws -> SwiftSymbol {
		let name: SwiftSymbol
		if scanner.conditional(scalar: "S") {
			let index = try demangleSwift3SubstitutionIndex()
			switch index.kind {
			case .protocol: name = index
			case .module: name = try demangleSwift3ProtocolNameGivenContext(context: index)
			default: throw scanner.unexpectedError()
			}
		} else if scanner.conditional(scalar: "s") {
			let stdlib = SwiftSymbol(kind: .module, contents: .name(stdlibName))
			name = try demangleSwift3ProtocolNameGivenContext(context: stdlib)
		} else {
			name = try demangleSwift3DeclarationName(kind: .protocol)
		}
		
		return SwiftSymbol(kind: .type, children: [name])
	}
	
	mutating func demangleSwift3ProtocolNameGivenContext(context: SwiftSymbol) throws -> SwiftSymbol {
		let name = try demangleSwift3DeclName()
		let result = SwiftSymbol(kind: .protocol, children: [context, name])
		nameStack.append(result)
		return result
	}
	
	mutating func demangleSwift3NominalType() throws -> SwiftSymbol {
		switch try scanner.readScalar() {
		case "S": return try demangleSwift3SubstitutionIndex()
		case "V": return try demangleSwift3DeclarationName(kind: .structure)
		case "O": return try demangleSwift3DeclarationName(kind: .enum)
		case "C": return try demangleSwift3DeclarationName(kind: .class)
		case "P": return try demangleSwift3DeclarationName(kind: .protocol)
		default: throw scanner.unexpectedError()
		}
	}
	
	mutating func demangleSwift3BoundGenericArgs(nominalType initialNominal: SwiftSymbol) throws -> SwiftSymbol {
		guard var parentOrModule = initialNominal.children.first else { throw scanner.unexpectedError() }
		
		let nominalType: SwiftSymbol
		switch parentOrModule.kind {
		case .module: fallthrough
		case .function: fallthrough
		case .extension: nominalType = initialNominal
		default:
			parentOrModule = try demangleSwift3BoundGenericArgs(nominalType: parentOrModule)
			
			guard initialNominal.children.count > 1 else { throw scanner.unexpectedError() }
			nominalType = SwiftSymbol(kind: initialNominal.kind, children: [parentOrModule, initialNominal.children[1]])
		}
		
		var children = [SwiftSymbol]()
		while !scanner.conditional(scalar: "_") {
			children.append(try demangleSwift3Type())
		}
		if children.isEmpty {
			return nominalType
		}
		let args = SwiftSymbol(kind: .typeList, children: children)
		let unboundType = SwiftSymbol(kind: .type, children: [nominalType])
		switch nominalType.kind {
		case .class: return SwiftSymbol(kind: .boundGenericClass, children: [unboundType, args])
		case .structure: return SwiftSymbol(kind: .boundGenericStructure, children: [unboundType, args])
		case .enum: return SwiftSymbol(kind: .boundGenericEnum, children: [unboundType, args])
		default: throw scanner.unexpectedError()
		}
	}
	
	mutating func demangleSwift3Entity() throws -> SwiftSymbol {
		let isStatic = scanner.conditional(scalar: "Z")
		
		let basicKind: SwiftSymbol.Kind
		switch try scanner.readScalar() {
		case "F": basicKind = .function
		case "v": basicKind = .variable
		case "I": basicKind = .initializer
		case "i": basicKind = .subscript
		default:
			try scanner.backtrack()
			return try demangleSwift3NominalType()
		}
		
		let context = try demangleSwift3Context()
		let kind: SwiftSymbol.Kind
		let hasType: Bool
		var name: SwiftSymbol? = nil
		var wrapEntity: Bool = false
		
		let c = try scanner.readScalar()
		switch c {
		case "Z": (kind, hasType) = (.isolatedDeallocator, false)
		case "D": (kind, hasType) = (.deallocator, false)
		case "d": (kind, hasType) = (.destructor, false)
		case "e": (kind, hasType) = (.iVarInitializer, false)
		case "E": (kind, hasType) = (.iVarDestroyer, false)
		case "C": (kind, hasType) = (.allocator, true)
		case "c": (kind, hasType) = (.constructor, true)
		case "a": fallthrough
		case "l":
			wrapEntity = true
			switch try scanner.readScalar() {
			case "O": (kind, hasType, name) = (c == "a" ? .owningMutableAddressor : .owningAddressor, true, try demangleSwift3DeclName())
			case "o": (kind, hasType, name) = (c == "a" ? .nativeOwningMutableAddressor : .nativeOwningAddressor, true, try demangleSwift3DeclName())
			case "p": (kind, hasType, name) = (c == "a" ? .nativePinningMutableAddressor : .nativePinningAddressor, true, try demangleSwift3DeclName())
			case "u": (kind, hasType, name) = (c == "a" ? .unsafeMutableAddressor : .unsafeAddressor, true, try demangleSwift3DeclName())
			default: throw scanner.unexpectedError()
			}
		case "g": (kind, hasType, name, wrapEntity) = (.getter, true, try demangleSwift3DeclName(), true)
		case "G": (kind, hasType, name, wrapEntity) = (.globalGetter, true, try demangleSwift3DeclName(), true)
		case "s": (kind, hasType, name, wrapEntity) = (.setter, true, try demangleSwift3DeclName(), true)
		case "m": (kind, hasType, name, wrapEntity) = (.materializeForSet, true, try demangleSwift3DeclName(), true)
		case "w": (kind, hasType, name, wrapEntity) = (.willSet, true, try demangleSwift3DeclName(), true)
		case "W": (kind, hasType, name, wrapEntity) = (.didSet, true, try demangleSwift3DeclName(), true)
		case "U": (kind, hasType, name) = (.explicitClosure, true, SwiftSymbol(kind: .number, contents: .index(try demangleSwift3Index())))
		case "u": (kind, hasType, name) = (.implicitClosure, true, SwiftSymbol(kind: .number, contents: .index(try demangleSwift3Index())))
		case "A" where basicKind == .initializer: (kind, hasType, name) = (.defaultArgumentInitializer, false, SwiftSymbol(kind: .number, contents: .index(try demangleSwift3Index())))
		case "i" where basicKind == .initializer: (kind, hasType) = (.initializer, false)
		case _ where basicKind == .initializer: throw scanner.unexpectedError()
		default:
			try scanner.backtrack()
			(kind, hasType, name) = (basicKind, true, try demangleSwift3DeclName())
		}
		
		var entity = SwiftSymbol(kind: kind)
		if wrapEntity {
			var isSubscript = false
			switch name?.kind {
			case .some(.identifier):
				if name?.text == "subscript" {
					isSubscript = true
					name = nil
				}
			case .some(.privateDeclName):
				if let n = name, let first = n.children.at(0), let second = n.children.at(1), second.text == "subscript" {
					isSubscript = true
					name = SwiftSymbol(kind: .privateDeclName, children: [first])
				}
			default: break
			}
			var wrappedEntity: SwiftSymbol
			if isSubscript {
				wrappedEntity = SwiftSymbol(kind: .subscript, child: context)
			} else {
				wrappedEntity = SwiftSymbol(kind: .variable, child: context)
			}
			if !isSubscript, let n = name {
				wrappedEntity.children.append(n)
			}
			if hasType {
				wrappedEntity.children.append(try demangleSwift3Type())
			}
			if isSubscript, let n = name {
				wrappedEntity.children.append(n)
			}
			entity.children.append(wrappedEntity)
		} else {
			entity.children.append(context)
			if let n = name {
				entity.children.append(n)
			}
			if hasType {
				entity.children.append(try demangleSwift3Type())
			}
		}
		
		return isStatic ? SwiftSymbol(kind: .static, children: [entity]) : entity
	}
	
	mutating func demangleSwift3DeclarationName(kind: SwiftSymbol.Kind) throws -> SwiftSymbol {
		let result = SwiftSymbol(kind: kind, children: [try demangleSwift3Context(), try demangleSwift3DeclName()])
		nameStack.append(result)
		return result
	}
	
	mutating func demangleSwift3Context() throws -> SwiftSymbol {
		switch try scanner.readScalar() {
		case "E": return SwiftSymbol(kind: .extension, children: [try demangleSwift3Module(), try demangleSwift3Context()])
		case "e":
			let module = try demangleSwift3Module()
			let signature = try demangleSwift3GenericSignature()
			let type = try demangleSwift3Context()
			return SwiftSymbol(kind: .extension, children: [module, type, signature])
		case "S": return try demangleSwift3SubstitutionIndex()
		case "s": return SwiftSymbol(kind: .module, children: [], contents: .name(stdlibName))
		case "G": return try demangleSwift3BoundGenericArgs(nominalType: demangleSwift3NominalType())
		case "F": fallthrough
		case "I": fallthrough
		case "v": fallthrough
		case "P": fallthrough
		case "Z": fallthrough
		case "C": fallthrough
		case "V": fallthrough
		case "O":
			try scanner.backtrack()
			return try demangleSwift3Entity()
		default:
			try scanner.backtrack()
			return try demangleSwift3Module()
		}
	}
	
	mutating func demangleSwift3Module() throws -> SwiftSymbol {
		switch try scanner.readScalar() {
		case "S": return try demangleSwift3SubstitutionIndex()
		case "s": return SwiftSymbol(kind: .module, children: [], contents: .name("Swift"))
		default:
			try scanner.backtrack()
			let module = try demangleSwift3Identifier(kind: .module)
			nameStack.append(module)
			return module
		}
	}
	
	func swiftStdLibType(_ kind: SwiftSymbol.Kind, named: String) -> SwiftSymbol {
		return SwiftSymbol(kind: kind, children: [SwiftSymbol(kind: .module, contents: .name(stdlibName)), SwiftSymbol(kind: .identifier, contents: .name(named))])
	}
	
	mutating func demangleSwift3SubstitutionIndex() throws -> SwiftSymbol {
		switch try scanner.readScalar() {
		case "o": return SwiftSymbol(kind: .module, contents: .name(objcModule))
		case "C": return SwiftSymbol(kind: .module, contents: .name(cModule))
		case "a": return swiftStdLibType(.structure, named: "Array")
		case "b": return swiftStdLibType(.structure, named: "Bool")
		case "c": return swiftStdLibType(.structure, named: "UnicodeScalar")
		case "d": return swiftStdLibType(.structure, named: "Double")
		case "f": return swiftStdLibType(.structure, named: "Float")
		case "i": return swiftStdLibType(.structure, named: "Int")
		case "V": return swiftStdLibType(.structure, named: "UnsafeRawPointer")
		case "v": return swiftStdLibType(.structure, named: "UnsafeMutableRawPointer")
		case "P": return swiftStdLibType(.structure, named: "UnsafePointer")
		case "p": return swiftStdLibType(.structure, named: "UnsafeMutablePointer")
		case "q": return swiftStdLibType(.enum, named: "Optional")
		case "Q": return swiftStdLibType(.enum, named: "ImplicitlyUnwrappedOptional")
		case "R": return swiftStdLibType(.structure, named: "UnsafeBufferPointer")
		case "r": return swiftStdLibType(.structure, named: "UnsafeMutableBufferPointer")
		case "S": return swiftStdLibType(.structure, named: "String")
		case "u": return swiftStdLibType(.structure, named: "UInt")
		default:
			try scanner.backtrack()
			let index = try demangleSwift3Index()
			if Int(index) >= nameStack.count {
				throw scanner.unexpectedError()
			}
			return nameStack[Int(index)]
		}
	}
	
	mutating func demangleSwift3GenericSignature(isPseudo: Bool = false) throws -> SwiftSymbol {
		var children = [SwiftSymbol]()
		var c = try scanner.requirePeek()
		while c != "R" && c != "r" {
			children.append(SwiftSymbol(kind: .dependentGenericParamCount, contents: .index(scanner.conditional(scalar: "z") ? 0 : (try demangleSwift3Index() + 1))))
			c = try scanner.requirePeek()
		}
		if children.isEmpty {
			children.append(SwiftSymbol(kind: .dependentGenericParamCount, contents: .index(1)))
		}
		if !scanner.conditional(scalar: "r") {
			try scanner.match(scalar: "R")
			while !scanner.conditional(scalar: "r") {
				children.append(try demangleSwift3GenericRequirement())
			}
		}
		return SwiftSymbol(kind: .dependentGenericSignature, children: children)
	}
	
	mutating func demangleSwift3GenericRequirement() throws -> SwiftSymbol {
		let constrainedType = try demangleSwift3ConstrainedType()
		if scanner.conditional(scalar: "z") {
			return SwiftSymbol(kind: .dependentGenericSameTypeRequirement, children: [constrainedType, try demangleSwift3Type()])
		}
		
		if scanner.conditional(scalar: "l") {
			let name: String
			let kind: SwiftSymbol.Kind
			var size = UInt64.max
			var alignment = UInt64.max
			switch try scanner.readScalar() {
			case "U": (kind, name) = (.identifier, "U")
			case "R": (kind, name) = (.identifier, "R")
			case "N": (kind, name) = (.identifier, "N")
			case "T": (kind, name) = (.identifier, "T")
			case "E":
				(kind, name) = (.identifier, "E")
				size = try require(demangleNatural())
				try scanner.match(scalar: "_")
				alignment = try require(demangleNatural())
			case "e":
				(kind, name) = (.identifier, "e")
				size = try require(demangleNatural())
			case "M":
				(kind, name) = (.identifier, "M")
				size = try require(demangleNatural())
				try scanner.match(scalar: "_")
				alignment = try require(demangleNatural())
			case "m":
				(kind, name) = (.identifier, "m")
				size = try require(demangleNatural())
			default: throw failure
			}
			let second = SwiftSymbol(kind: kind, contents: .name(name))
			var reqt = SwiftSymbol(kind: .dependentGenericLayoutRequirement, children: [constrainedType, second])
			if size != UInt64.max {
				reqt.children.append(SwiftSymbol(kind: .number, contents: .index(size)))
				if alignment != UInt64.max {
					reqt.children.append(SwiftSymbol(kind: .number, contents: .index(alignment)))
				}
			}
			return reqt
		}
		
		let c = try scanner.requirePeek()
		let constraint: SwiftSymbol
		if c == "C" {
			constraint = try demangleSwift3Type()
		} else if c == "S" {
			try scanner.match(scalar: "S")
			let index = try demangleSwift3SubstitutionIndex()
			let typename: SwiftSymbol
			switch index.kind {
			case .protocol: fallthrough
			case .class: typename = index
			case .module: typename = try demangleSwift3ProtocolNameGivenContext(context: index)
			default: throw scanner.unexpectedError()
			}
			constraint = SwiftSymbol(kind: .type, children: [typename])
		} else {
			constraint = try demangleSwift3ProtocolName()
		}
		return SwiftSymbol(kind: .dependentGenericConformanceRequirement, children: [constrainedType, constraint])
	}
	
	mutating func demangleSwift3ConstrainedType() throws -> SwiftSymbol {
		if scanner.conditional(scalar: "w") {
			return try demangleSwift3AssociatedTypeSimple()
		} else if scanner.conditional(scalar: "W") {
			return try demangleSwift3AssociatedTypeCompound()
		}
		return try demangleSwift3GenericParamIndex()
	}
	
	mutating func demangleSwift3AssociatedTypeSimple() throws -> SwiftSymbol {
		let base = try demangleSwift3GenericParamIndex()
		return try demangleSwift3DependentMemberTypeName(base: SwiftSymbol(kind: .type, children: [base]))
	}
	
	mutating func demangleSwift3AssociatedTypeCompound() throws -> SwiftSymbol {
		var base = try demangleSwift3GenericParamIndex()
		while !scanner.conditional(scalar: "_") {
			let type = SwiftSymbol(kind: .type, children: [base])
			base = try demangleSwift3DependentMemberTypeName(base: type)
		}
		return base
	}
	
	mutating func demangleSwift3GenericParamIndex() throws -> SwiftSymbol {
		let depth: UInt64
		let index: UInt64
		switch try scanner.readScalar() {
		case "d": (depth, index) = (try demangleSwift3Index() + 1, try demangleSwift3Index())
		case "x": (depth, index) = (0, 0)
		default:
			try scanner.backtrack()
			(depth, index) = (0, try demangleSwift3Index() + 1)
		}
		return SwiftSymbol(kind: .dependentGenericParamType, children: [SwiftSymbol(kind: .index, contents: .index(depth)), SwiftSymbol(kind: .index, contents: .index(index))], contents: .name(archetypeName(index, depth)))
	}
	
	mutating func demangleSwift3DependentMemberTypeName(base: SwiftSymbol) throws -> SwiftSymbol {
		let associatedType: SwiftSymbol
		if scanner.conditional(scalar: "S") {
			associatedType = try demangleSwift3SubstitutionIndex()
		} else {
			var prot: SwiftSymbol? = nil
			if scanner.conditional(scalar: "P") {
				prot = try demangleSwift3ProtocolName()
			}
			let identifier = try demangleSwift3Identifier()
			if let p = prot {
				associatedType = SwiftSymbol(kind: .dependentAssociatedTypeRef, children: [identifier, p])
			} else {
				associatedType = SwiftSymbol(kind: .dependentAssociatedTypeRef, children: [identifier])
			}
			nameStack.append(associatedType)
		}
		
		return SwiftSymbol(kind: .dependentMemberType, children: [base, associatedType])
	}
	
	mutating func demangleSwift3DeclName() throws -> SwiftSymbol {
		switch try scanner.readScalar() {
		case "L": return SwiftSymbol(kind: .localDeclName, children: [SwiftSymbol(kind: .number, contents: .index(try demangleSwift3Index())), try demangleSwift3Identifier()])
		case "P": return SwiftSymbol(kind: .privateDeclName, children: [try demangleSwift3Identifier(), try demangleSwift3Identifier()])
		default:
			try scanner.backtrack()
			return try demangleSwift3Identifier()
		}
	}
	
	mutating func demangleSwift3Index() throws -> UInt64 {
		if scanner.conditional(scalar: "_") {
			return 0
		}
		let value = UInt64(try scanner.readInt()) + 1
		try scanner.match(scalar: "_")
		return value
	}
	
	mutating func demangleSwift3Type() throws -> SwiftSymbol {
		let type: SwiftSymbol
		switch try scanner.readScalar() {
		case "B":
			switch try scanner.readScalar() {
			case "b": type = SwiftSymbol(kind: .builtinTypeName, contents: .name("Builtin.BridgeObject"))
			case "B": type = SwiftSymbol(kind: .builtinTypeName, contents: .name("Builtin.UnsafeValueBuffer"))
			case "f":
				let size = try scanner.readInt()
				try scanner.match(scalar: "_")
				type = SwiftSymbol(kind: .builtinTypeName, contents: .name("Builtin.FPIEEE\(size)"))
			case "i":
				let size = try scanner.readInt()
				try scanner.match(scalar: "_")
				type = SwiftSymbol(kind: .builtinTypeName, contents: .name("Builtin.Int\(size)"))
			case "v":
				let elements = try scanner.readInt()
				try scanner.match(scalar: "B")
				let name: String
				let size: String
				let c = try scanner.readScalar()
				switch c {
				case "p": (name, size) = ("xRawPointer", "")
				case "i": fallthrough
				case "f":
					(name, size) = (c == "i" ? "xInt" : "xFPIEEE", try "\(scanner.readInt())")
					try scanner.match(scalar: "_")
				default: throw scanner.unexpectedError()
				}
				type = SwiftSymbol(kind: .builtinTypeName, contents: .name("Builtin.Vec\(elements)\(name)\(size)"))
			case "O": type = SwiftSymbol(kind: .builtinTypeName, contents: .name("Builtin.UnknownObject"))
			case "o": type = SwiftSymbol(kind: .builtinTypeName, contents: .name("Builtin.NativeObject"))
			case "t": type = SwiftSymbol(kind: .builtinTypeName, contents: .name("Builtin.SILToken"))
			case "p": type = SwiftSymbol(kind: .builtinTypeName, contents: .name("Builtin.RawPointer"))
			case "w": type = SwiftSymbol(kind: .builtinTypeName, contents: .name("Builtin.Word"))
			default: throw scanner.unexpectedError()
			}
		case "a": type = try demangleSwift3DeclarationName(kind: .typeAlias)
		case "b": type = try demangleSwift3FunctionType(kind: .objCBlock)
		case "c": type = try demangleSwift3FunctionType(kind: .cFunctionPointer)
		case "D": type = SwiftSymbol(kind: .dynamicSelf, children: [try demangleSwift3Type()])
		case "E":
			guard try scanner.readScalars(count: 2) == "RR" else { throw scanner.unexpectedError() }
			type = SwiftSymbol(kind: .errorType, children: [], contents: .name(""))
		case "F": type = try demangleSwift3FunctionType(kind: .functionType)
		case "f": type = try demangleSwift3FunctionType(kind: .uncurriedFunctionType)
		case "G": type = try demangleSwift3BoundGenericArgs(nominalType: demangleSwift3NominalType())
		case "X":
			let c = try scanner.readScalar()
			switch c {
			case "b": type = SwiftSymbol(kind: .silBoxType, children: [try demangleSwift3Type()])
			case "B":
				var signature: SwiftSymbol? = nil
				if scanner.conditional(scalar: "G") {
					signature = try demangleSwift3GenericSignature(isPseudo: false)
				}
				var layout = SwiftSymbol(kind: .silBoxLayout)
				while !scanner.conditional(scalar: "_") {
					let kind: SwiftSymbol.Kind
					switch try scanner.readScalar() {
					case "m": kind = .silBoxMutableField
					case "i": kind = .silBoxImmutableField
					default: throw failure
					}
					let type = try demangleType()
					let field = SwiftSymbol(kind: kind, child: type)
					layout.children.append(field)
				}
				var genericArgs: SwiftSymbol? = nil
				if signature != nil {
					var ga = SwiftSymbol(kind: .typeList)
					while !scanner.conditional(scalar: "_") {
						let type = try demangleType()
						ga.children.append(type)
					}
					genericArgs = ga
				}
				var boxType = SwiftSymbol(kind: .silBoxTypeWithLayout, child: layout)
				if let s = signature, let ga = genericArgs {
					boxType.children.append(s)
					boxType.children.append(ga)
				}
				return boxType
			case "P" where scanner.conditional(scalar: "M"): fallthrough
			case "M":
				let value: String
				switch try scanner.readScalar() {
				case "t": value = "@thick"
				case "T": value = "@thin"
				case "o": value = "@objc_metatype"
				default: throw scanner.unexpectedError()
				}
				type = SwiftSymbol(kind: c == "P" ? .existentialMetatype : .metatype, children: [SwiftSymbol(kind: .metatypeRepresentation, contents: .name(value)), try demangleSwift3Type()])
			case "P":
				var children = [SwiftSymbol]()
				while !scanner.conditional(scalar: "_") {
					children.append(try demangleSwift3ProtocolName())
				}
				type = SwiftSymbol(kind: .protocolList, children: [SwiftSymbol(kind: .typeList)])
			case "f": type = try demangleSwift3FunctionType(kind: .thinFunctionType)
			case "o": type = SwiftSymbol(kind: .unowned, children: [try demangleSwift3Type()])
			case "u": type = SwiftSymbol(kind: .unmanaged, children: [try demangleSwift3Type()])
			case "w": type = SwiftSymbol(kind: .weak, children: [try demangleSwift3Type()])
			case "F":
				var children = [SwiftSymbol]()
				children.append(SwiftSymbol(kind: .implConvention, contents: .name(try demangleSwift3ImplConvention(kind: .implConvention))))
				if scanner.conditional(scalar: "C") {
					let name: String
					switch try scanner.readScalar() {
					case "b": name = "@convention(block)"
					case "c": name = "@convention(c)"
					case "m": name = "@convention(method)"
					case "O": name = "@convention(objc_method)"
					case "w": name = "@convention(witness_method)"
					default: throw scanner.unexpectedError()
					}
					children.append(SwiftSymbol(kind: .implFunctionAttribute, contents: .name(name)))
				}
				if scanner.conditional(scalar: "G") {
					children.append(try demangleSwift3GenericSignature(isPseudo: false))
				} else if scanner.conditional(scalar: "g") {
					children.append(try demangleSwift3GenericSignature(isPseudo: true))
				}
				try scanner.match(scalar: "_")
				while !scanner.conditional(scalar: "_") {
					children.append(try demangleSwift3ImplParameterOrResult(kind: .implParameter))
				}
				while !scanner.conditional(scalar: "_") {
					children.append(try demangleSwift3ImplParameterOrResult(kind: .implResult))
				}
				type = SwiftSymbol(kind: .implFunctionType, children: children)
			default: throw scanner.unexpectedError()
			}
		case "K": type = try demangleSwift3FunctionType(kind: .autoClosureType)
		case "M": type = SwiftSymbol(kind: .metatype, children: [try demangleSwift3Type()])
		case "P" where scanner.conditional(scalar: "M"): type = SwiftSymbol(kind: .existentialMetatype, children: [try demangleSwift3Type()])
		case "P":
			var children = [SwiftSymbol]()
			while !scanner.conditional(scalar: "_") {
				children.append(try demangleSwift3ProtocolName())
			}
			type = SwiftSymbol(kind: .protocolList, children: [SwiftSymbol(kind: .typeList, children: children)])
		case "Q":
			if scanner.conditional(scalar: "u") {
				type = SwiftSymbol(kind: .opaqueReturnType)
			} else if scanner.conditional(scalar: "U") {
				let index = try demangleIndex()
				type = SwiftSymbol(kind: .opaqueReturnType, child: SwiftSymbol(kind: .opaqueReturnTypeIndex, contents: .index(index)))
			} else {
				type = try demangleSwift3ArchetypeType()
			}
		case "q":
			let c = try scanner.requirePeek()
			if c != "d" && c != "_" && c < "0" && c > "9" {
				type = try demangleSwift3DependentMemberTypeName(base: demangleSwift3Type())
			} else {
				type = try demangleSwift3GenericParamIndex()
			}
		case "x": type = SwiftSymbol(kind: .dependentGenericParamType, children: [SwiftSymbol(kind: .index, contents: .index(0)), SwiftSymbol(kind: .index, contents: .index(0))], contents: .name(archetypeName(0, 0)))
		case "w": type = try demangleSwift3AssociatedTypeSimple()
		case "W": type = try demangleSwift3AssociatedTypeCompound()
		case "R": type = SwiftSymbol(kind: .inOut, children: try demangleSwift3Type().children)
		case "S": type = try demangleSwift3SubstitutionIndex()
		case "T": type = try demangleSwift3Tuple(variadic: false)
		case "t": type = try demangleSwift3Tuple(variadic: true)
		case "u": type = SwiftSymbol(kind: .dependentGenericType, children: [try demangleSwift3GenericSignature(), try demangleSwift3Type()])
		case "C": type = try demangleSwift3DeclarationName(kind: .class)
		case "V": type = try demangleSwift3DeclarationName(kind: .structure)
		case "O": type = try demangleSwift3DeclarationName(kind: .enum)
		default: throw scanner.unexpectedError()
		}
		return SwiftSymbol(kind: .type, children: [type])
	}
	
	mutating func demangleSwift3ArchetypeType() throws -> SwiftSymbol {
		switch try scanner.readScalar() {
		case "Q":
			let result = SwiftSymbol(kind: .associatedTypeRef, children: [try demangleSwift3ArchetypeType(), try demangleSwift3Identifier()])
			nameStack.append(result)
			return result
		case "S":
			let index = try demangleSwift3SubstitutionIndex()
			let result = SwiftSymbol(kind: .associatedTypeRef, children: [index, try demangleSwift3Identifier()])
			nameStack.append(result)
			return result
		case "s":
			let root = SwiftSymbol(kind: .module, contents: .name(stdlibName))
			let result = SwiftSymbol(kind: .associatedTypeRef, children: [root, try demangleSwift3Identifier()])
			nameStack.append(result)
			return result
		default: throw scanner.unexpectedError()
		}
	}
	
	mutating func demangleSwift3ImplConvention(kind: SwiftSymbol.Kind) throws -> String {
		let scalar = try scanner.readScalar()
		switch (scalar, (kind == .implErrorResult ? .implResult : kind)) {
		case ("a", .implResult): return "@autoreleased"
		case ("d", .implConvention): return "@callee_unowned"
		case ("d", _): return "@unowned"
		case ("D", .implResult): return "@unowned_inner_pointer"
		case ("g", .implParameter): return "@guaranteed"
		case ("e", .implParameter): return "@deallocating"
		case ("g", .implConvention): return "@callee_guaranteed"
		case ("i", .implParameter): return "@in"
		case ("i", .implResult): return "@out"
		case ("l", .implParameter): return "@inout"
		case ("o", .implConvention): return "@callee_owned"
		case ("o", _): return "@owned"
		case ("t", .implConvention): return "@convention(thin)"
		default: throw scanner.unexpectedError()
		}
	}
	
	mutating func demangleSwift3ImplParameterOrResult(kind: SwiftSymbol.Kind) throws -> SwiftSymbol {
		var k: SwiftSymbol.Kind
		if scanner.conditional(scalar: "z") {
			if case .implResult = kind {
				k = .implErrorResult
			} else {
				throw scanner.unexpectedError()
			}
		} else {
			k = kind
		}
		
		let convention = try demangleSwift3ImplConvention(kind: k)
		let type = try demangleSwift3Type()
		let conventionNode = SwiftSymbol(kind: .implConvention, contents: .name(convention))
		return SwiftSymbol(kind: k, children: [conventionNode, type])
	}
	
	
	mutating func demangleSwift3Tuple(variadic: Bool) throws -> SwiftSymbol {
		var children = [SwiftSymbol]()
		while !scanner.conditional(scalar: "_") {
			var elementChildren = [SwiftSymbol]()
			let peek = try scanner.requirePeek()
			if (peek >= "0" && peek <= "9") || peek == "o" {
				elementChildren.append(try demangleSwift3Identifier(kind: .tupleElementName))
			}
			elementChildren.append(try demangleSwift3Type())
			children.append(SwiftSymbol(kind: .tupleElement, children: elementChildren))
		}
		if variadic, var last = children.popLast() {
			last.children.insert(SwiftSymbol(kind: .variadicMarker), at: 0)
			children.append(last)
		}
		return SwiftSymbol(kind: .tuple, children: children)
	}
	
	mutating func demangleSwift3FunctionType(kind: SwiftSymbol.Kind) throws -> SwiftSymbol {
		var children = [SwiftSymbol]()
		if scanner.conditional(scalar: "z") {
			children.append(SwiftSymbol(kind: .throwsAnnotation))
		}
		children.append(SwiftSymbol(kind: .argumentTuple, children: [try demangleSwift3Type()]))
		children.append(SwiftSymbol(kind: .returnType, children: [try demangleSwift3Type()]))
		return SwiftSymbol(kind: kind, children: children)
	}
	
	mutating func demangleSwift3Identifier(kind: SwiftSymbol.Kind? = nil) throws -> SwiftSymbol {
		let isPunycode = scanner.conditional(scalar: "X")
		let k: SwiftSymbol.Kind
		let isOperator: Bool
		if scanner.conditional(scalar: "o") {
			guard kind == nil else { throw scanner.unexpectedError() }
			switch try scanner.readScalar() {
			case "p": (isOperator, k) = (true, .prefixOperator)
			case "P": (isOperator, k) = (true, .postfixOperator)
			case "i": (isOperator, k) = (true, .infixOperator)
			default: throw scanner.unexpectedError()
			}
		} else {
			(isOperator, k) = (false, kind ?? SwiftSymbol.Kind.identifier)
		}
		
		var identifier = try scanner.readScalars(count: Int(scanner.readInt()))
		if isPunycode {
			identifier = try decodeSwiftPunycode(identifier)
		}
		if isOperator {
			let source = identifier
			identifier = ""
			for scalar in source.unicodeScalars {
				switch scalar {
				case "a": identifier.unicodeScalars.append("&" as UnicodeScalar)
				case "c": identifier.unicodeScalars.append("@" as UnicodeScalar)
				case "d": identifier.unicodeScalars.append("/" as UnicodeScalar)
				case "e": identifier.unicodeScalars.append("=" as UnicodeScalar)
				case "g": identifier.unicodeScalars.append(">" as UnicodeScalar)
				case "l": identifier.unicodeScalars.append("<" as UnicodeScalar)
				case "m": identifier.unicodeScalars.append("*" as UnicodeScalar)
				case "n": identifier.unicodeScalars.append("!" as UnicodeScalar)
				case "o": identifier.unicodeScalars.append("|" as UnicodeScalar)
				case "p": identifier.unicodeScalars.append("+" as UnicodeScalar)
				case "q": identifier.unicodeScalars.append("?" as UnicodeScalar)
				case "r": identifier.unicodeScalars.append("%" as UnicodeScalar)
				case "s": identifier.unicodeScalars.append("-" as UnicodeScalar)
				case "t": identifier.unicodeScalars.append("~" as UnicodeScalar)
				case "x": identifier.unicodeScalars.append("^" as UnicodeScalar)
				case "z": identifier.unicodeScalars.append("." as UnicodeScalar)
				default:
					if scalar.value >= 128 {
						identifier.unicodeScalars.append(scalar)
					} else {
						throw scanner.unexpectedError()
					}
				}
			}
		}
		
		return SwiftSymbol(kind: k, children: [], contents: .name(identifier))
	}
}

fileprivate func archetypeName(_ index: UInt64, _ depth: UInt64) -> String {
	var result = ""
	var i = index
	repeat {
		result.unicodeScalars.append(UnicodeScalar(("A" as UnicodeScalar).value + UInt32(i % 26))!)
		i /= 26
	} while i > 0
	if depth != 0 {
		result += depth.description
	}
	return result
}

// MARK: Punycode.h

/// Rough adaptation of the pseudocode from 6.2 "Decoding procedure" in RFC3492
fileprivate func decodeSwiftPunycode(_ value: String) throws -> String {
	let input = value.unicodeScalars
	var output = [UnicodeScalar]()
	
	var pos = input.startIndex
	
	// Unlike RFC3492, Swift uses underscore for delimiting
	if let ipos = input.lastIndex(of: "_" as UnicodeScalar) {
		output.append(contentsOf: input[input.startIndex..<ipos].map { UnicodeScalar($0) })
		pos = input.index(ipos, offsetBy: 1)
	}
	
	// Magic numbers from RFC3492
	var n = 128
	var i = 0
	var bias = 72
	let symbolCount = 36
	let alphaCount = 26
	while pos != input.endIndex {
		let oldi = i
		var w = 1
		for k in stride(from: symbolCount, to: Int.max, by: symbolCount) {
			// Unlike RFC3492, Swift uses letters A-J for values 26-35
			let digit: Int
			if input[pos] >= UnicodeScalar("a") {
				digit = Int(input[pos].value - UnicodeScalar("a").value)
			} else if input[pos] >= UnicodeScalar("A") {
				digit = Int((input[pos].value - UnicodeScalar("A").value) + UInt32(alphaCount))
			} else {
				throw SwiftSymbolParseError.punycodeParseError
			}
			
			if pos != input.endIndex {
				pos = input.index(pos, offsetBy: 1)
			}
			
			i = i &+ (digit &* w)
			let t = max(min(k - bias, alphaCount), 1)
			if (digit < t) {
				break
			}
			w = w &* (symbolCount - t)
		}
		
		// Bias adaptation function
		var delta = (i - oldi) / ((oldi == 0) ? 700 : 2)
		delta = delta + delta / (output.count + 1)
		var k = 0
		while (delta > 455) {
			delta = delta / (symbolCount - 1)
			k = k + symbolCount
		}
		k += (symbolCount * delta) / (delta + symbolCount + 2)
		
		bias = k
		n = n + i / (output.count + 1)
		i = i % (output.count + 1)
		let validScalar = UnicodeScalar(n) ?? UnicodeScalar(".")
		output.insert(validScalar, at: i)
		i += 1
	}
	return String(output.map { Character($0) })
}

// MARK: SwiftSymbol extensions for printing

fileprivate extension SwiftSymbol.Kind {
	var isExistentialType: Bool {
		switch self {
		case .existentialMetatype, .protocolList, .protocolListWithClass, .protocolListWithAnyObject: return true
		default: return false
		}
	}
}

fileprivate extension SwiftSymbol {
	var isSimpleType: Bool {
		switch kind {
		case .associatedType: fallthrough
		case .associatedTypeRef: fallthrough
		case .boundGenericClass: fallthrough
		case .boundGenericEnum: fallthrough
		case .boundGenericFunction: fallthrough
		case .boundGenericOtherNominalType: fallthrough
		case .boundGenericProtocol: fallthrough
		case .boundGenericStructure: fallthrough
		case .boundGenericTypeAlias: fallthrough
		case .builtinTypeName: fallthrough
		case .builtinTupleType: fallthrough
		case .builtinFixedArray: fallthrough
		case .class: fallthrough
		case .dependentGenericType: fallthrough
		case .dependentMemberType: fallthrough
		case .dependentGenericParamType: fallthrough
		case .dynamicSelf: fallthrough
		case .enum: fallthrough
		case .errorType: fallthrough
		case .existentialMetatype: fallthrough
		case .integer: fallthrough
		case .labelList: fallthrough
		case .metatype: fallthrough
		case .metatypeRepresentation: fallthrough
		case .module: fallthrough
		case .negativeInteger: fallthrough
		case .otherNominalType: fallthrough
		case .pack: fallthrough
		case .protocol: fallthrough
		case .protocolSymbolicReference: fallthrough
		case .returnType: fallthrough
		case .silBoxType: fallthrough
		case .silBoxTypeWithLayout: fallthrough
		case .structure: fallthrough
		case .sugaredArray: fallthrough
		case .sugaredDictionary: fallthrough
		case .sugaredOptional: fallthrough
		case .sugaredParen: return true
		case .tuple: fallthrough
		case .tupleElementName: fallthrough
		case .typeAlias: fallthrough
		case .typeList: fallthrough
		case .typeSymbolicReference: fallthrough
		case .type:
			return self.children.first.map { $0.isSimpleType } ?? false
		case .protocolList:
			return children.first.map { $0.children.count <= 1 } ?? false
		case .protocolListWithAnyObject:
			return (children.first?.children.first).map { $0.children.count == 0 } ?? false
		default: return false
		}
	}
	
	var needSpaceBeforeType: Bool {
		switch self.kind {
		case .type: return children.first?.needSpaceBeforeType ?? false
		case .functionType, .noEscapeFunctionType, .uncurriedFunctionType, .dependentGenericType: return false
		default: return true
		}
	}
	
	func isIdentifier(desired: String) -> Bool {
		return kind == .identifier && text == desired
	}
	
	var isSwiftModule: Bool {
		return kind == .module && text == stdlibName
	}
}

fileprivate enum SugarType {
	case none
	case optional
	case implicitlyUnwrappedOptional
	case array
	case dictionary
}

fileprivate enum TypePrinting {
	case noType
	case withColon
	case functionStyle
}

// MARK: SymbolPrinter

fileprivate struct SymbolPrinter {
	var target: String
	var specializationPrefixPrinted: Bool
	var options: SymbolPrintOptions
	var hidingCurrentModule: String = ""
	
	init(options: SymbolPrintOptions = .default) {
		self.target = ""
		self.specializationPrefixPrinted = false
		self.options = options
	}
	
	func shouldPrintContext(_ context: SwiftSymbol) -> Bool {
		guard options.contains(.qualifyEntities) else {
			return false
		}
		if context.kind == .module, let text = context.text, !text.isEmpty {
			switch text {
			case stdlibName: return options.contains(.displayStdlibModule)
			case objcModule: return options.contains(.displayObjCModule)
			case hidingCurrentModule: return false
			default:
				if text.starts(with: lldbExpressionsModuleNamePrefix) {
					return options.contains(.displayDebuggerGeneratedModule)
				}
			}
		}
		return true
		
	}
	
	mutating func printOptional(_ optional: SwiftSymbol?, prefix: String? = nil, suffix: String? = nil, asPrefixContext: Bool = false) -> SwiftSymbol? {
		guard let o = optional else { return nil }
		prefix.map { target.write($0) }
		let r = printName(o)
		suffix.map { target.write($0) }
		return r
	}
	
	mutating func printFirstChild(_ ofName: SwiftSymbol, prefix: String? = nil, suffix: String? = nil, asPrefixContext: Bool = false) {
		_ = printOptional(ofName.children.at(0), prefix: prefix, suffix: suffix)
	}
	
	mutating func printSequence<S>(_ names: S, prefix: String? = nil, suffix: String? = nil, separator: String? = nil) where S: Sequence, S.Element == SwiftSymbol {
		var isFirst = true
		prefix.map { target.write($0) }
		for c in names {
			if let s = separator, !isFirst {
				target.write(s)
			} else {
				isFirst = false
			}
			_ = printName(c)
		}
		suffix.map { target.write($0) }
	}
	
	mutating func printChildren(_ ofName: SwiftSymbol, prefix: String? = nil, suffix: String? = nil, separator: String? = nil) {
		printSequence(ofName.children, prefix: prefix, suffix: suffix, separator: separator)
	}
	
	mutating func printMacro(name: SwiftSymbol, asPrefixContext: Bool, label: String) -> SwiftSymbol? {
		return printEntity(name, asPrefixContext: asPrefixContext, typePrinting: .noType, hasName: true, extraName: "\(label) macro @\(name.children.at(2)?.description ?? "") expansion #", extraIndex: (name.children.at(3)?.index ?? 0) + 1)
	}
	
	mutating func printAnonymousContext(_ name: SwiftSymbol) {
		if options.contains(.qualifyEntities) && options.contains(.displayExtensionContexts) {
			_ = printOptional(name.children.at(1))
			target.write(".(unknown context at " + (name.children.first?.text ?? "") + ")")
			if let second = name.children.at(2), !second.children.isEmpty {
				target.write("<")
				_ = printName(second)
				target.write(">")
			}
		}
	}
	
	mutating func printExtension(_ name: SwiftSymbol) {
		if options.contains(.qualifyEntities) && options.contains(.displayExtensionContexts) {
			printFirstChild(name, prefix: "(extension in ", suffix: "):", asPrefixContext: true)
		}
		_ = printOptional(name.children.at(1))
		_ = printOptional(!options.contains(.printForTypeName) ? name.children.at(2) : nil)
	}
	
	mutating func printSuffix(_ name: SwiftSymbol) {
		if options.contains(.displayUnmangledSuffix) {
			target.write(" with unmangled suffix ")
			quotedString(name.text ?? "")
		}
	}
	
	mutating func printPrivateDeclName(_ name: SwiftSymbol) {
		_ = printOptional(name.children.at(1), prefix: options.contains(.showPrivateDiscriminators) ? "(" : nil)
		target.write(options.contains(.showPrivateDiscriminators) ? "\(name.children.count > 1 ? " " : "(")in \(name.children.at(0)?.text ?? ""))" : "")
	}
	
	mutating func printModule(_ name: SwiftSymbol) {
		if options.contains(.displayModuleNames) {
			target.write(name.text ?? "")
		}
	}
	
	mutating func printReturnType(_ name: SwiftSymbol) {
		if name.children.isEmpty, let t = name.text {
			target.write(t)
		} else {
			printChildren(name)
		}
	}
	
	mutating func printRetroactiveConformance(_ name: SwiftSymbol) {
		if name.children.count == 2 {
			printChildren(name, prefix: "retroactive @ ")
		}
	}
	
	mutating func printGenericSpecializationParam(_ name: SwiftSymbol) {
		printFirstChild(name)
		_ = printOptional(name.children.at(1), prefix: " with ")
		name.children.slice(2, name.children.endIndex).forEach {
			target.write(" and ")
			_ = printName($0)
		}
	}
	
	mutating func printFunctionSignatureSpecializationParam(_ name: SwiftSymbol) {
		var idx = 0
		while idx < name.children.count {
			guard let firstChild = name.children.at(idx), let v = firstChild.index else { return }
			let k = FunctionSigSpecializationParamKind(rawValue: v)
			switch k {
			case .boxToValue, .boxToStack, .inOutToOut:
				_ = printOptional(name.children.at(idx))
				idx += 1
			case .constantPropFunction, .constantPropGlobal:
				_ = printOptional(name.children.at(idx), prefix: "[", suffix: " : ")
				guard let t = name.children.at(idx + 1)?.text else { return }
				let demangedName = (try? parseMangledSwiftSymbol(t))?.description ?? ""
				if demangedName.isEmpty {
					target.write(t)
				} else {
					target.write(demangedName)
				}
				target.write("]")
				idx += 2
			case .constantPropInteger: fallthrough
			case .constantPropFloat:
				_ = printOptional(name.children.at(idx), prefix: "[")
				_ = printOptional(name.children.at(idx + 1), prefix: " : ", suffix: "]")
				idx += 2
			case .constantPropString:
				_ = printOptional(name.children.at(idx), prefix: "[")
				_ = printOptional(name.children.at(idx + 1), prefix: " : ")
				_ = printOptional(name.children.at(idx + 2), prefix: "'", suffix: "']")
				idx += 3
			case .constantPropKeyPath:
				_ = printOptional(name.children.at(idx), prefix: "[")
				_ = printOptional(name.children.at(idx + 1), prefix: " : ")
				_ = printOptional(name.children.at(idx + 2), prefix: "<")
				_ = printOptional(name.children.at(idx + 3), prefix: ",", suffix: ">]")
				idx += 4
			case .closureProp:
				_ = printOptional(name.children.at(idx), prefix: "[")
				_ = printOptional(name.children.at(idx + 1), prefix: " : ", suffix: ", Argument Types : [")
				idx += 2
				while idx < name.children.count, let c = name.children.at(idx), c.kind == .type {
					_ = printName(c)
					idx += 1
					if idx < name.children.count && name.children.at(idx)?.text != nil {
						target.write(", ")
					}
				}
				target.write("]")
			default:
				_ = printOptional(name.children.at(idx))
				idx += 1
			}
		}
	}
	
	mutating func printFunctionSignatureSpecializationParamKind(_ name: SwiftSymbol) {
		let raw = name.index ?? 0
		var printedOptionSet = false
		if raw & FunctionSigSpecializationParamKind.existentialToGeneric.rawValue != 0 {
			printedOptionSet = true
			target.write(FunctionSigSpecializationParamKind.existentialToGeneric.description)
		}
		if raw & FunctionSigSpecializationParamKind.dead.rawValue != 0 {
			if printedOptionSet { target.write(" and ") }
			printedOptionSet = true
			target.write(FunctionSigSpecializationParamKind.dead.description)
		}
		if raw & FunctionSigSpecializationParamKind.ownedToGuaranteed.rawValue != 0 {
			if printedOptionSet { target.write(" and ") }
			printedOptionSet = true
			target.write(FunctionSigSpecializationParamKind.ownedToGuaranteed.description)
		}
		if raw & FunctionSigSpecializationParamKind.guaranteedToOwned.rawValue != 0 {
			if printedOptionSet { target.write(" and ") }
			printedOptionSet = true
			target.write(FunctionSigSpecializationParamKind.guaranteedToOwned.description)
		}
		if raw & FunctionSigSpecializationParamKind.sroa.rawValue != 0 {
			if printedOptionSet { target.write(" and ") }
			printedOptionSet = true
			target.write(FunctionSigSpecializationParamKind.sroa.description)
		}
		
		if printedOptionSet {
			return
		}
		
		if let single = FunctionSigSpecializationParamKind(rawValue: raw) {
			target.write(single.description)
		}
	}
	
	mutating func printLazyProtocolWitnesstableAccessor(_ name: SwiftSymbol) {
		_ = printOptional(name.children.at(0), prefix: "lazy protocol witness table accessor for type ")
		_ = printOptional(name.children.at(1), prefix: " and conformance ")
	}
	
	mutating func printLazyProtocolWitnesstableCacheVariable(_ name: SwiftSymbol) {
		_ = printOptional(name.children.at(0), prefix: "lazy protocol witness table cache variable for type ")
		_ = printOptional(name.children.at(1), prefix: " and conformance ")
	}
	
	mutating func printVTableThunk(_ name: SwiftSymbol) {
		_ = printOptional(name.children.at(1), prefix: "vtable thunk for ")
		_ = printOptional(name.children.at(0), prefix: " dispatching to ")
	}
	
	mutating func printProtocolWitness(_ name: SwiftSymbol) {
		_ = printOptional(name.children.at(1), prefix: "protocol witness for ")
		_ = printOptional(name.children.at(0), prefix: " in conformance ")
	}
	
	mutating func printPartialApplyForwarder(_ name: SwiftSymbol) {
		target.write("partial apply\(options.contains(.shortenPartialApply) ? "" : " forwarder")")
		if !name.children.isEmpty {
			printChildren(name, prefix: " for ")
		}
	}
	
	mutating func printPartialApplyObjCForwarder(_ name: SwiftSymbol) {
		target.write("partial apply\(options.contains(.shortenPartialApply) ? "" : " ObjC forwarder")")
		if !name.children.isEmpty {
			printChildren(name, prefix: " for ")
		}
	}
	
	mutating func printKeyPathAccessorThunkHelper(_ name: SwiftSymbol) {
		printFirstChild(name, prefix: "key path \(name.kind == .keyPathGetterThunkHelper ? "getter" : "setter") for ", suffix: " : ")
		for child in name.children.dropFirst() {
			if child.kind == .isSerialized {
				target.write(", ")
			}
			_ = printName(child)
		}
	}
	
	mutating func printKeyPathEqualityThunkHelper(_ name: SwiftSymbol) {
		target.write("key path index \(name.kind == .keyPathEqualsThunkHelper ? "equality" : "hash") operator for ")
		var dropLast = false
		if let lastChild = name.children.last, lastChild.kind == .dependentGenericSignature {
			_ = printName(lastChild)
			dropLast = true
		}
		printSequence(dropLast ? Array(name.children.dropLast()) : name.children, prefix: "(", suffix: ")", separator: ", ")
	}
	
	mutating func printFieldOffset(_ name: SwiftSymbol) {
		printFirstChild(name)
		_ = printOptional(name.children.at(1), prefix: "field offset for ", asPrefixContext: true)
	}
	
	mutating func printReabstractionThunk(_ name: SwiftSymbol) {
		if options.contains(.shortenThunk) {
			_ = printOptional(name.children.at(name.children.count - 2), prefix: "thunk for ")
		} else {
			target.write("reabstraction thunk ")
			target.write(name.kind == .reabstractionThunkHelper ? "helper " : "")
			_ = printOptional(name.children.at(name.children.count - 3), suffix: " ")
			_ = printOptional(name.children.at(name.children.count - 1), prefix: "from ")
			_ = printOptional(name.children.at(name.children.count - 2), prefix: " to ")
		}
	}
	
	mutating func printAssociatedConformanceDescriptor(_ name: SwiftSymbol) {
		_ = printOptional(name.children.at(0), prefix: "associated conformance descriptor for ")
		_ = printOptional(name.children.at(1), prefix: ".")
		_ = printOptional(name.children.at(2), prefix: ": ")
	}
	
	mutating func printDefaultAssociatedConformanceAccessor(_ name: SwiftSymbol) {
		_ = printOptional(name.children.at(0), prefix: "default associated conformance accessor for ")
		_ = printOptional(name.children.at(1), prefix: ".")
		_ = printOptional(name.children.at(2), prefix: ": ")
	}
	
	mutating func printAssociatedTypeMetadataAccessor(_ name: SwiftSymbol) {
		_ = printOptional(name.children.at(1), prefix: "associated type metadata accessor for ")
		_ = printOptional(name.children.at(0), prefix: " in ")
	}
	
	mutating func printAssociatedTypeWitnessTableAccessor(_ name: SwiftSymbol) {
		_ = printOptional(name.children.at(1), prefix: "associated type witness table accessor for ")
		_ = printOptional(name.children.at(2), prefix: " : ")
		_ = printOptional(name.children.at(0), prefix: " in ")
	}
	
	mutating func printValueWitness(_ name: SwiftSymbol) {
		target.write(ValueWitnessKind(rawValue: name.index ?? 0)?.description ?? "")
		target.write(options.contains(.shortenValueWitness) ? " for " : " value witness for ")
		printFirstChild(name)
	}
	
	mutating func printConcreteProtocolConformance(_ name: SwiftSymbol) {
		target.write("concrete protocol conformance ")
		if let index = name.index {
			target.write(" #\(index)")
		}
		printFirstChild(name)
		target.write(" to ")
		_ = printOptional(name.children.at(1))
		if let thirdChild = name.children.at(2), !thirdChild.children.isEmpty {
			target.write(" with conditional requirements: ")
			_ = printName(thirdChild)
		}
	}
	
	mutating func printMetatype(_ name: SwiftSymbol) {
		if name.children.count == 2 {
			printFirstChild(name, suffix: " ")
		}
		guard let type = name.children.at(name.children.count == 2 ? 1 : 0)?.children.first else { return }
		let needParens = !type.isSimpleType
		target.write(needParens ? "(" : "")
		_ = printName(type)
		target.write(needParens ? ")" : "")
		target.write(type.kind.isExistentialType ? ".Protocol" : ".Type")
	}
	
	mutating func printExistentialMetatype(_ name: SwiftSymbol) {
		if name.children.count == 2 {
			printFirstChild(name, suffix: " ")
		}
		_ = printOptional(name.children.at(name.children.count == 2 ? 1 : 0), suffix: ".Type")
	}
	
	mutating func printAssociatedTypeRef(_ name: SwiftSymbol) {
		printFirstChild(name)
		target.write(".\(name.children.at(1)?.text ?? "")")
	}
	
	mutating func printProtocolList(_ name: SwiftSymbol) {
		guard let typeList = name.children.first else { return }
		if typeList.children.isEmpty {
			target.write("Any")
		} else {
			printChildren(typeList, separator: " & ")
		}
	}
	
	mutating func printProtocolListWithClass(_ name: SwiftSymbol) {
		guard name.children.count >= 2 else { return }
		_ = printOptional(name.children.at(1), suffix: " & ")
		if let protocolsTypeList = name.children.first?.children.first {
			printChildren(protocolsTypeList, separator: " & ")
		}
	}
	
	mutating func printProtocolListWithAnyObject(_ name: SwiftSymbol) {
		guard let prot = name.children.first, let protocolsTypeList = prot.children.first else { return }
		if protocolsTypeList.children.count > 0 {
			printChildren(protocolsTypeList, suffix: " & ", separator: " & ")
		}
		if options.contains(.qualifyEntities) {
			target.write("Swift.")
		}
		target.write("AnyObject")
	}
	
	mutating func printProtocolConformance(_ name: SwiftSymbol) {
		if name.children.count == 4 {
			_ = printOptional(name.children.at(2), prefix: "property behavior storage of ")
			_ = printOptional(name.children.at(0), prefix: " in ")
			_ = printOptional(name.children.at(1), prefix: " : ")
		} else {
			printFirstChild(name)
			if options.contains(.displayProtocolConformances) {
				_ = printOptional(name.children.at(1), prefix: " : ")
				_ = printOptional(name.children.at(2), prefix: " in ")
			}
		}
	}
	
	mutating func printImplParameter(_ name: SwiftSymbol) {
		printFirstChild(name, suffix: " ")
		if name.children.count == 3 {
			_ = printOptional(name.children.at(1))
		} else if name.children.count == 4 {
			_ = printOptional(name.children.at(1))
			_ = printOptional(name.children.at(2))
		}
		_ = printOptional(name.children.last)
	}
	
	mutating func printDependentProtocolConformanceAssociated(_ name: SwiftSymbol) {
		target.write("dependent associated protocol conformance ")
		if let index = name.children.at(2)?.index {
			target.write("#\(index) ")
		}
		printFirstChild(name)
		target.write(" to ")
		_ = printOptional(name.children.at(1))
	}
	
	mutating func printDependentProtocolConformanceInherited(_ name: SwiftSymbol) {
		target.write("dependent inherited protocol conformance ")
		if let index = name.children.at(2)?.index {
			target.write("#\(index) ")
		}
		printFirstChild(name)
		target.write(" to ")
		_ = printOptional(name.children.at(1))
	}
	
	mutating func printDependentProtocolConformanceRoot(_ name: SwiftSymbol) {
		target.write("dependent root protocol conformance ")
		if let index = name.children.at(2)?.index {
			target.write("#\(index) ")
		}
		printFirstChild(name)
		target.write(" to ")
		_ = printOptional(name.children.at(1))
	}
	
	static func genericParameterName(depth: UInt64, index: UInt64) -> String {
		var name = ""
		var index = index
		repeat {
			if let scalar = UnicodeScalar(UnicodeScalar("A").value + UInt32(index % 26)) {
				name.unicodeScalars.append(scalar)
			}
			index /= 26
		} while (index != 0)
		if (depth != 0) {
			name.append("\(depth)")
		}
		return name
	}
	
	mutating func printGenericSignature(_ name: SwiftSymbol) {
		target.write("<")
		var numGenericParams = 0
		for c in name.children {
			guard c.kind == .dependentGenericParamCount else { break }
			numGenericParams += 1
		}
		var firstRequirement = numGenericParams
		for var c in name.children.dropFirst(numGenericParams) {
			if c.kind == .type {
				c = c.children.first ?? c
			}
			guard c.kind == .dependentGenericParamPackMarker || c.kind == .dependentGenericParamValueMarker else {
				break
			}
			firstRequirement += 1
		}
		
		let isGenericParamPack = { (depth: UInt64, index: UInt64) -> Bool in
			for var child in name.children.dropFirst(numGenericParams).prefix(firstRequirement) {
				guard child.kind == .dependentGenericParamPackMarker else { continue }
				
				child = child.children.first ?? child
				guard child.kind == .type else { continue }
				
				child = child.children.first ?? child
				guard child.kind == .dependentGenericParamType else { continue }
				
				if index == child.children.at(0)?.index, depth == child.children.at(1)?.index {
					return true
				}
			}
			
			return false;
		}
		
		let isGenericParamValue = { (depth: UInt64, index: UInt64) -> SwiftSymbol? in
			for var child in name.children.dropFirst(numGenericParams).prefix(firstRequirement) {
				guard child.kind == .dependentGenericParamValueMarker else { continue }
				child = child.children.first ?? child
				
				guard child.kind == .type else { continue }
				
				guard
					let param = child.children.at(0),
					let type = child.children.at(1),
					param.kind == .dependentGenericParamType
				else {
					continue
				}
				
				if index == param.children.at(0)?.index, depth == param.children.at(1)?.index {
					return type
				}
			}
			
			return nil
		}
		
		for gpDepth in 0..<numGenericParams {
			if gpDepth != 0 {
				target.write("><")
			}
			
			guard let count = name.children.at(gpDepth)?.index else { continue }
			for index in 0..<count {
				if index != 0 {
					target.write(", ")
				}
				
				// Limit the number of printed generic parameters. In practice this
				// it will never be exceeded. The limit is only important for malformed
				// symbols where count can be really huge.
				if index >= 128 {
					target.write("...")
					break;
				}
				
				if isGenericParamPack(UInt64(gpDepth), UInt64(index)) {
					target.write("each ")
				}
				
				let value = isGenericParamValue(UInt64(gpDepth), UInt64(index))
				if value != nil {
					target.write("let ")
				}
				
				target.write(Self.genericParameterName(depth: UInt64(gpDepth), index: UInt64(index)))
				
				if let value {
					target.write(": ")
					_ = printName(value)
				}
			}
		}
		
		if firstRequirement != name.children.count {
			if options.contains(.displayWhereClauses) {
				target.write(" where ")
				printSequence(name.children.dropFirst(firstRequirement), separator: ", ")
			}
		}
		target.write(">")
	}
	
	mutating func printDependentGenericConformanceRequirement(_ name: SwiftSymbol) {
		printFirstChild(name)
		_ = printOptional(name.children.at(1), prefix: ": ")
	}
	
	mutating func printDependentGenericLayoutRequirement(_ name: SwiftSymbol) {
		guard let layout = name.children.at(1), let c = layout.text?.unicodeScalars.first else { return }
		printFirstChild(name, suffix: ": ")
		switch c {
		case "U": target.write("_UnknownLayout")
		case "R": target.write("_RefCountedObject")
		case "N": target.write("_NativeRefCountedObject")
		case "C": target.write("AnyObject")
		case "D": target.write("_NativeClass")
		case "T": target.write("_Trivial")
		case "E", "e": target.write("_Trivial")
		case "M", "m": target.write("_TrivialAtMost")
		default: break
		}
		if name.children.count > 2 {
			_ = printOptional(name.children.at(2), prefix: "(")
			_ = printOptional(name.children.at(3), prefix: ", ")
			target.write(")")
		}
	}
	
	mutating func printDependentGenericSameTypeRequirement(_ name: SwiftSymbol) {
		printFirstChild(name)
		_ = printOptional(name.children.at(1), prefix: " == ")
	}
	
	mutating func printDependentGenericType(_ name: SwiftSymbol) {
		guard let depType = name.children.at(1) else { return }
		printFirstChild(name)
		_ = printOptional(depType, prefix: depType.needSpaceBeforeType ? " " : "")
	}
	
	mutating func printDependentMemberType(_ name: SwiftSymbol) {
		printFirstChild(name)
		target.write(".")
		_ = printOptional(name.children.at(1))
	}
	
	mutating func printDependentAssociatedTypeRef(_ name: SwiftSymbol) {
		_ = printOptional(name.children.at(1), suffix: ".")
		printFirstChild(name)
	}
	
	mutating func printSilBoxTypeWithLayout(_ name: SwiftSymbol) {
		guard let layout = name.children.first else { return }
		_ = printOptional(name.children.at(1), suffix: " ")
		_ = printName(layout)
		if let genericArgs = name.children.at(2) {
			printSequence(genericArgs.children, prefix: " <", suffix: ">", separator: ", ")
		}
	}
	
	mutating func printSugaredOptional(_ name: SwiftSymbol) {
		if let type = name.children.first {
			let needParens = !type.isSimpleType
			target.write(needParens ? "(" : "")
			_ = printName(type)
			target.write(needParens ? ")" : "")
			target.write("?")
		}
	}
	
	mutating func printSugaredDictionary(_ name: SwiftSymbol) {
		printFirstChild(name, prefix: "[", suffix: " : ")
		_ = printOptional(name.children.at(1), suffix: "]")
	}
	
	mutating func printOpaqueType(_ name: SwiftSymbol) {
		printFirstChild(name)
		target.write(".")
		_ = printOptional(name.children.at(1))
	}
	
	mutating func printImplInvocationsSubstitutions(_ name: SwiftSymbol) {
		if let secondChild = name.children.at(0) {
			target.write(" for <")
			printChildren(secondChild, separator: ", ")
			target.write(">")
		}
	}
	
	mutating func printImplPatternSubstitutions(_ name: SwiftSymbol) {
		target.write("@substituted ")
		printFirstChild(name)
		if let secondChild = name.children.at(1) {
			target.write(" for <")
			printChildren(secondChild, separator: ", ")
			target.write(">")
		}
	}
	
	mutating func printImplDifferentiability(_ name: SwiftSymbol) {
		if let text = name.text, !text.isEmpty {
			target.write("\(text) ")
		}
	}
	
	mutating func printMacroExpansionLoc(_ name: SwiftSymbol) {
		if let module = name.children.at(0) {
			target.write("module ")
			_ = printName(module)
		}
		if let file = name.children.at(1) {
			target.write(" file ")
			_ = printName(file)
		}
		if let line = name.children.at(2) {
			target.write(" line ")
			_ = printName(line)
		}
		if let column = name.children.at(3) {
			target.write(" column ")
			_ = printName(column)
		}
	}
	
	mutating func printGlobalActorFunctionType(_ name: SwiftSymbol) {
		if let firstChild = name.children.first {
			target.write("@")
			_ = printName(firstChild)
			target.write(" ")
		}
	}
	
	mutating func printGlobalVariableOnceFunction(_ name: SwiftSymbol) {
		target.write(name.kind == .globalVariableOnceToken ? "one-time initialization token for " : "one-time initialization function for ")
		if let firstChild = name.children.first, shouldPrintContext(firstChild) {
			_ = printName(firstChild)
		}
	}
	
	mutating func printGlobalVariableOnceDeclList(_ name: SwiftSymbol) {
		if name.children.count == 1 {
			printFirstChild(name)
		} else {
			printSequence(name.children, prefix: "(", suffix: ")", separator: ", ")
		}
	}
	
	mutating func printTypeThrowsAnnotation(_ name: SwiftSymbol) {
		target.write(" throws(")
		if let child = name.children.first {
			_ = printName(child)
		}
		target.write(")")
	}
	
	mutating func printDifferentiableFunctionType(_ name: SwiftSymbol) {
		target.write("@differentiable")
		switch UnicodeScalar(UInt8(name.index ?? 0)) {
		case "f": target.write("(_forward)")
		case "r": target.write("(reverse)")
		case "l": target.write("(_linear)")
		default: break
		}
	}
	
	mutating func printDifferentiabilityWitness(_ name: SwiftSymbol) {
		let kindNodeIndex = name.children.count - (name.children.last?.kind == .dependentGenericSignature ? 4 : 3)
		let kind = (name.children.at(kindNodeIndex)?.index).flatMap { Differentiability($0) }
		switch kind {
		case .forward: target.write("forward-mode")
		case .reverse: target.write("reverse-mode")
		case .normal: target.write("normal")
		case .linear: target.write("linear")
		default: return
		}
		target.write(" differentiability witness for ")
		var idx = 0
		while idx < name.children.count && name.children.at(idx)?.kind != .index {
			_ = printOptional(name.children.at(idx))
			idx += 1
		}
		_ = printOptional(name.children.at(idx + 1), prefix: " with respect to parameters ")
		_ = printOptional(name.children.at(idx + 2), prefix: " and results ")
		_ = printOptional(name.children.at(idx + 3), prefix: " with ")
	}
	
	mutating func printAsyncAwaitResumePartialFunction(_ name: SwiftSymbol) {
		if options.contains(.showAsyncResumePartial) {
			target.write("(")
			_ = printName(name.children.first!)
			target.write(")")
			target.write(" await resume partial function for ")
		}
	}
	
	mutating func printAsyncSuspendResumePartialFunction(_ name: SwiftSymbol) {
		if options.contains(.showAsyncResumePartial) {
			target.write("(")
			_ = printName(name.children.first!)
			target.write(")")
			target.write(" suspend resume partial function for ")
		}
	}
	
	mutating func printExtendedExistentialTypeShape(_ name: SwiftSymbol) {
		let savedDisplayWhereClauses = options.contains(.displayWhereClauses)
		options.insert(.displayWhereClauses)
		var genSig: SwiftSymbol?
		let type: SwiftSymbol
		if name.children.count == 2 {
			genSig = name.children[0]
			type = name.children[1]
		} else {
			type = name.children[0]
		}
		target.write("existential shape for ")
		if let genSig {
			_ = printName(genSig)
			target.write(" ")
		}
		target.write("any ")
		_ = printName(type)
		if !savedDisplayWhereClauses {
			options.remove(.displayWhereClauses)
		}
	}
	
	mutating func printSymbolicExtendedExistentialType(_ name: SwiftSymbol) {
		guard let shape = name.children.first else { return }
		let isUnique = shape.kind == .uniqueExtendedExistentialTypeShapeSymbolicReference
		target.write("symbolic existential type (\(isUnique ? "" : "non-")unique) 0x")
		target.writeHex(shape.index ?? 0)
		target.write(" <")
		guard let second = name.children.at(1) else { return }
		_ = printName(second)
		if let third = name.children.at(2) {
			target.write(", ")
			_ = printName(third)
		}
		target.write(">")
	}
	
	mutating func printTupleElement(_ name: SwiftSymbol) {
		if let label = name.children.first(where: { $0.kind == .tupleElementName }) {
			target.write("\(label.text ?? ""): ")
		}
		guard let type = name.children.first(where: { $0.kind == .type }) else { return }
		_ = printName(type)
		if let _ = name.children.first(where: { $0.kind == .variadicMarker }) {
			target.write("...")
		}
	}
	
	mutating func printObjCAsyncCompletionHandlerImpl(_ name: SwiftSymbol) {
		if name.kind == .predefinedObjCAsyncCompletionHandlerImpl {
			target.write("predefined ")
		}
		target.write("@objc completion handler block implementation for ")
		if name.children.count >= 4 {
			_ = printOptional(name.children.at(3))
		}
		printFirstChild(name, suffix: " with result type ")
		_ = printOptional(name.children.at(1))
		switch name.children.at(2)?.index {
		case 0: break
		case 1: target.write(" nonzero on error ")
		case 2: target.write(" zero on error ")
		default: target.write(" <invalid error flag>")
		}
	}
	
	mutating func printImplInvocationSubstitutions(_ name: SwiftSymbol) {
		if let secondChild = name.children.at(0) {
			target.write(" for <")
			printChildren(secondChild, separator: ", ")
			target.write(">")
		}
	}
	
	mutating func printImplDifferentiabilityKind(_ name: SwiftSymbol) {
		target.write("@differentiable")
		if case .index(let value) = name.contents, let differentiability = Differentiability(value) {
			switch differentiability {
			case .normal: break
			case .linear: target.write("(_linear)")
			case .forward: target.write("(_forward)")
			case .reverse: target.write("(reverse)")
			}
		}
	}
	
	mutating func printImplCoroutineKind(_ name: SwiftSymbol) {
		guard case .name(let value) = name.contents, !value.isEmpty else { return }
		target.write("@\(value)")
	}
	
	mutating func printImplFunctionConvention(_ name: SwiftSymbol) {
		target.write("@convention(")
		if let second = name.children.at(1) {
			target.write("\(name.children.at(0)?.text ?? ""), mangledCType: \"")
			_ = printName(second)
			target.write("\"")
		} else {
			target.write("\(name.children.at(0)?.text ?? "")")
		}
		target.write(")")
	}
	
	mutating func printImplParameterName(_ name: SwiftSymbol) {
		guard case .name(let value) = name.contents, !value.isEmpty else { return }
		target.write("\(value) ")
	}
	
	mutating func printBaseConformanceDescriptor(_ name: SwiftSymbol) {
		printFirstChild(name, prefix: "base conformance descriptor for ")
		_ = printOptional(name.children.at(1), prefix: ": ")
	}
	
	mutating func printReabstractionThunkHelperWithSelf(_ name: SwiftSymbol) {
		target.write("reabstraction thunk ")
		var idx = 0
		if name.children.count == 4 {
			printFirstChild(name, suffix: " ")
			idx += 1
		}
		_ = printOptional(name.children.at(idx + 2), prefix: "from ")
		_ = printOptional(name.children.at(idx + 1), prefix: " to ")
		_ = printOptional(name.children.at(idx), prefix: " self ")
	}
	
	mutating func printReabstracctionThunkHelperWithGlobalActor(_ name: SwiftSymbol) {
		printFirstChild(name)
		_ = printOptional(name.children.at(1), prefix: " with global actor constraint")
	}
	
	mutating func printBuildInFixedArray(_ name: SwiftSymbol) {
		_ = printOptional(name.children.first, prefix: "Builtin.FixedArray<")
		_ = printOptional(name.children.at(1), prefix: ", ", suffix: ">")
	}
	
	mutating func printAutoDiffFunctionOrSimpleThunk(_ name: SwiftSymbol) {
		var prefixEndIndex = 0
		while prefixEndIndex < name.children.count && name.children[prefixEndIndex].kind != .autoDiffFunctionKind {
			prefixEndIndex += 1
		}
		
		let funcKind = name.children.at(prefixEndIndex)
		let paramIndices = name.children.at(prefixEndIndex + 1)
		let resultIndices = name.children.at(prefixEndIndex + 2)
		if name.kind == .autoDiffDerivativeVTableThunk {
			target.write("vtable thunk for ")
		}
		_ = printOptional(funcKind)
		target.write(" of ")
		var optionalGenSig: SwiftSymbol?
		for i in 0..<prefixEndIndex {
			if i == prefixEndIndex - 1, name.children.at(i)?.kind == .dependentGenericSignature {
				optionalGenSig = name.children.at(i)
				break
			}
			_ = printOptional(name.children.at(i))
		}
		if options.contains(.shortenThunk) {
			return
		}
		target.write(" with respect to parameters ")
		_ = printOptional(paramIndices)
		target.write(" and results ")
		_ = printOptional(resultIndices)
		_ = printOptional(options.contains(.displayWhereClauses) ? optionalGenSig : nil, prefix: " with ")
	}
	
	mutating func printAutoDiffFunctionKind(_ name: SwiftSymbol) {
		guard let kind = name.index else { return }
		switch AutoDiffFunctionKind(kind) {
		case .forward: target.write("forward-mode derivative")
		case .reverse: target.write("reverse-mode derivative")
		case .differential: target.write("differential")
		case .pullback: target.write("pullback")
		default: break
		}
	}
	
	mutating func printAutoDiffSelfReorderingReabstractionThunk(_ name: SwiftSymbol) {
		target.write("autodiff self-reordering reabstraction thunk ")
		let fromType = name.children.first
		_ = printOptional(options.contains(.shortenThunk) ? fromType : nil, prefix: "for ")
		let toType = name.children.at(1)
		var kindIndex = 2
		var optionalGenSig: SwiftSymbol?
		if name.children.at(kindIndex)?.kind == .dependentGenericSignature {
			optionalGenSig = name.children.at(kindIndex)
			kindIndex += 1
		}
		target.write("for ")
		_ = printOptional(name.children.at(kindIndex))
		_ = printOptional(optionalGenSig, suffix: " ")
		_ = printOptional(fromType, prefix: " from ")
		_ = printOptional(toType, prefix: " to ")
	}
	
	mutating func printAutoDiffSubsetParametersThunk(_ name: SwiftSymbol) {
		target.write("autodiff subset parameters thunk for ")
		let lastIndex = name.children.count - 1
		let toParamIndices = name.children.at(lastIndex)
		let resultIndices = name.children.at(lastIndex - 1)
		let paramIndices = name.children.at(lastIndex - 2)
		let kind = name.children.at(lastIndex - 3)
		let currentIndex = lastIndex - 4
		_ = printOptional(kind, suffix: " from ")
		if currentIndex == 0 {
			printFirstChild(name)
		} else {
			printSequence(name.children.prefix(currentIndex))
		}
		if options.contains(.shortenThunk) {
			return
		}
		target.write(" with respect to parameters ")
		_ = printOptional(paramIndices)
		target.write(" and results ")
		_ = printOptional(resultIndices)
		target.write(" to parameters ")
		_ = printOptional(toParamIndices)
		_ = printOptional(currentIndex > 0 ? name.children.at(currentIndex) : nil, prefix: " of type ")
	}
	
	mutating func printIndexSubset(_ name: SwiftSymbol) {
		target.write("{")
		var printedAnyIndex = false
		for (i, c) in (name.text ?? "").enumerated() {
			if c != "S" {
				continue
			}
			if printedAnyIndex {
				target.write(", ")
			}
			target.write("\(i)")
			printedAnyIndex = true
		}
		target.write("}")
	}
	
	mutating func printBaseWitnessTableAccessor(_ name: SwiftSymbol) {
		_ = printOptional(name.children.at(1), prefix: "base witness table accessor for ")
		_ = printOptional(name.children.at(0), prefix: " in ")
	}
	
	mutating func printDependentGenericInverseConformanceRequirement(_ name: SwiftSymbol) {
		printFirstChild(name, suffix: ": ~")
		switch name.children.at(1)?.index {
		case 0: target.write("Swift.Copyable")
		case 1: target.write("Swift.Escapable")
		default: target.write("Swift.<bit \(name.children.at(1)?.index ?? 0)>")
		}
	}
	
	mutating func printDependentGenericSameShapeRequirement(_ name: SwiftSymbol) {
		_ = printOptional(name.children.at(0), suffix: ".shape == ")
		_ = printOptional(name.children.at(1), suffix: ".shape")
	}
	
	mutating func printConstrainedExistential(_ name: SwiftSymbol) {
		printFirstChild(name, prefix: "any ")
		_ = printOptional(name.children.at(1), prefix: "<", suffix: ">")
	}
	
	mutating func printName(_ name: SwiftSymbol, asPrefixContext: Bool = false) -> SwiftSymbol? {
		switch name.kind {
		case .accessibleFunctionRecord: target.write(conditional: !options.contains(.shortenThunk), "accessible function runtime record for ")
		case .accessorAttachedMacroExpansion: return printMacro(name: name, asPrefixContext: asPrefixContext, label: "accessor")
		case .accessorFunctionReference: target.write("accessor function at \(name.index ?? 0)")
		case .allocator: return printEntity(name, asPrefixContext: asPrefixContext, typePrinting: .functionStyle, hasName: false, extraName: (name.children.first?.kind == .class) ? "__allocating_init" : "init")
		case .anonymousContext: printAnonymousContext(name)
		case .anonymousDescriptor: printFirstChild(name, prefix: "anonymous descriptor ")
		case .anyProtocolConformanceList: printChildren(name, prefix: "(", suffix: ")", separator: ", ")
		case .argumentTuple: printFunctionParameters(labelList: nil, parameterType: name, showTypes: options.contains(.showFunctionArgumentTypes))
		case .associatedConformanceDescriptor: printAssociatedConformanceDescriptor(name)
		case .associatedType: return nil
		case .associatedTypeDescriptor: printFirstChild(name, prefix: "associated type descriptor for ")
		case .associatedTypeGenericParamRef: printChildren(name, prefix: "generic parameter reference for associated type ")
		case .associatedTypeMetadataAccessor: printAssociatedTypeMetadataAccessor(name)
		case .associatedTypeRef: printAssociatedTypeRef(name)
		case .associatedTypeWitnessTableAccessor: printAssociatedTypeWitnessTableAccessor(name)
		case .assocTypePath: printChildren(name, separator: ".")
		case .asyncAnnotation: target.write(" async")
		case .asyncAwaitResumePartialFunction: printAsyncAwaitResumePartialFunction(name)
		case .asyncFunctionPointer: target.write("async function pointer to ")
		case .asyncRemoved: printFirstChild(name, prefix: "async demotion of ")
		case .asyncSuspendResumePartialFunction: printAsyncSuspendResumePartialFunction(name)
		case .autoDiffFunction, .autoDiffDerivativeVTableThunk: printAutoDiffFunctionOrSimpleThunk(name)
		case .autoDiffFunctionKind: printAutoDiffFunctionKind(name)
		case .autoDiffSelfReorderingReabstractionThunk: printAutoDiffSelfReorderingReabstractionThunk(name)
		case .autoDiffSubsetParametersThunk: printAutoDiffSubsetParametersThunk(name)
		case .backDeploymentFallback: target.write(conditional: !options.contains(.shortenThunk), "back deployment fallback for ")
		case .backDeploymentThunk: target.write(conditional: !options.contains(.shortenThunk), "back deployment thunk for ")
		case .baseConformanceDescriptor: printBaseConformanceDescriptor(name)
		case .baseWitnessTableAccessor: printBaseWitnessTableAccessor(name)
		case .bodyAttachedMacroExpansion: return printMacro(name: name, asPrefixContext: asPrefixContext, label: "body")
		case .boundGenericClass, .boundGenericStructure, .boundGenericEnum, .boundGenericProtocol, .boundGenericOtherNominalType, .boundGenericTypeAlias: printBoundGeneric(name)
		case .builtinFixedArray: printBuildInFixedArray(name)
		case .builtinTupleType: target.write("Builtin.TheTupleType")
		case .builtinTypeName: target.write(name.text ?? "")
		case .canonicalPrespecializedGenericTypeCachingOnceToken: printFirstChild(name, prefix: "flag for loading of canonical specialized generic type metadata for ")
		case .canonicalSpecializedGenericMetaclass: printFirstChild(name, prefix: "specialized generic metaclass for ")
		case .canonicalSpecializedGenericTypeMetadataAccessFunction: printFirstChild(name, prefix: "canonical specialized generic type metadata accessor for ")
		case .cFunctionPointer, .objCBlock, .noEscapeFunctionType, .escapingAutoClosureType, .autoClosureType, .thinFunctionType, .functionType, .escapingObjCBlock, .uncurriedFunctionType: printFunctionType(name)
		case .clangType: target.write(name.text ?? "")
		case .class, .structure, .enum, .protocol, .typeAlias: return printEntity(name, asPrefixContext: asPrefixContext, typePrinting: .noType, hasName: true)
		case .classMetadataBaseOffset: printFirstChild(name, prefix: "class metadata base offset for ")
		case .compileTimeConst: printFirstChild(name, prefix: "_const ")
		case .concreteProtocolConformance: printConcreteProtocolConformance(name)
		case .concurrentFunctionType: target.write("@Sendable ")
		case .conformanceAttachedMacroExpansion: return printMacro(name: name, asPrefixContext: asPrefixContext, label: "conformance")
		case .constrainedExistential: printConstrainedExistential(name)
		case .constrainedExistentialRequirementList: printChildren(name, separator: ", ")
		case .constrainedExistentialSelf: target.write("Self")
		case .constructor: return printEntity(name, asPrefixContext: asPrefixContext, typePrinting: .functionStyle, hasName: name.children.count > 2, extraName: "init")
		case .coroutineContinuationPrototype: printFirstChild(name, prefix: "coroutine continuation prototype for ")
		case .curryThunk: printFirstChild(name, prefix: "curry thunk of ")
		case .deallocator: return printEntity(name, asPrefixContext: asPrefixContext, typePrinting: .noType, hasName: false, extraName: (name.children.first?.kind == .class) ? "__deallocating_deinit" : "deinit")
		case .declContext: printFirstChild(name)
		case .defaultArgumentInitializer: return printEntity(name, asPrefixContext: asPrefixContext, typePrinting: .noType, hasName: false, extraName: "default argument \(name.children.at(1)?.index ?? 0)")
		case .defaultAssociatedConformanceAccessor: printDefaultAssociatedConformanceAccessor(name)
		case .defaultAssociatedTypeMetadataAccessor: printFirstChild(name, prefix: "default associated type metadata accessor for ")
		case .dependentAssociatedConformance: printChildren(name, prefix: "dependent associated conformance ")
		case .dependentAssociatedTypeRef: printDependentAssociatedTypeRef(name)
		case .dependentGenericConformanceRequirement: printDependentGenericConformanceRequirement(name)
		case .dependentGenericInverseConformanceRequirement: printDependentGenericInverseConformanceRequirement(name)
		case .dependentGenericLayoutRequirement: printDependentGenericLayoutRequirement(name)
		case .dependentGenericParamCount: return nil
		case .dependentGenericParamPackMarker: break
		case .dependentGenericParamType: target.write(name.text ?? "")
		case .dependentGenericParamValueMarker: break
		case .dependentGenericSameShapeRequirement: printDependentGenericSameShapeRequirement(name)
		case .dependentGenericSameTypeRequirement: printDependentGenericSameTypeRequirement(name)
		case .dependentGenericType: printDependentGenericType(name)
		case .dependentMemberType: printDependentMemberType(name)
		case .dependentProtocolConformanceAssociated: printDependentProtocolConformanceAssociated(name)
		case .dependentProtocolConformanceInherited: printDependentProtocolConformanceInherited(name)
		case .dependentProtocolConformanceRoot: printDependentProtocolConformanceRoot(name)
		case .dependentPseudogenericSignature, .dependentGenericSignature: printGenericSignature(name)
		case .destructor: return printEntity(name, asPrefixContext: asPrefixContext, typePrinting: .noType, hasName: false, extraName: "deinit")
		case .didSet: return printAbstractStorage(name.children.first, asPrefixContext: asPrefixContext, extraName: "didset")
		case .differentiabilityWitness: printDifferentiabilityWitness(name)
		case .differentiableFunctionType: printDifferentiableFunctionType(name)
		case .directMethodReferenceAttribute: target.write("super ")
		case .directness: name.index.flatMap { Directness(rawValue: $0)?.description }.map { target.write("\($0) ") }
		case .dispatchThunk: printFirstChild(name, prefix: "dispatch thunk of ")
		case .distributedAccessor: target.write(conditional: !options.contains(.shortenThunk), "distributed accessor for ")
		case .distributedThunk: target.write(conditional: !options.contains(.shortenThunk), "distributed thunk ")
		case .droppedArgument: target.write("param\(name.index ?? 0)-removed")
		case .dynamicallyReplaceableFunctionImpl: target.write(conditional: !options.contains(.shortenThunk), "dynamically replaceable thunk for ")
		case .dynamicallyReplaceableFunctionKey: target.write(conditional: !options.contains(.shortenThunk), "dynamically replaceable key for ")
		case .dynamicallyReplaceableFunctionVar: target.write(conditional: !options.contains(.shortenThunk), "dynamically replaceable variable for ")
		case .dynamicAttribute: target.write("dynamic ")
		case .dynamicSelf: target.write("Self")
		case .emptyList: target.write(" empty-list ")
		case .enumCase: printFirstChild(name, prefix: "enum case for ", asPrefixContext: false)
		case .errorType: target.write("<ERROR TYPE>")
		case .existentialMetatype: printExistentialMetatype(name)
		case .explicitClosure: return printEntity(name, asPrefixContext: asPrefixContext, typePrinting: options.contains(.showFunctionArgumentTypes) ? .functionStyle : .noType, hasName: false, extraName: "closure #", extraIndex: (name.children.at(1)?.index ?? 0) + 1)
		case .extendedExistentialTypeShape: printExtendedExistentialTypeShape(name)
		case .extension: printExtension(name)
		case .extensionAttachedMacroExpansion: return printMacro(name: name, asPrefixContext: asPrefixContext, label: "extension")
		case .extensionDescriptor: printFirstChild(name, prefix: "extension descriptor ")
		case .fieldOffset: printFieldOffset(name)
		case .firstElementMarker: target.write(" first-element-marker ")
		case .freestandingMacroExpansion: return printEntity(name, asPrefixContext: asPrefixContext, typePrinting: .noType, hasName: true, extraName: "freestanding macro expansion #", extraIndex: (name.children.at(2)?.index ?? 0) + 1)
		case .fullObjCResilientClassStub: printFirstChild(name, prefix: "full ObjC resilient class stub for ")
		case .fullTypeMetadata: printFirstChild(name, prefix: "full type metadata for ")
		case .function, .boundGenericFunction: return printEntity(name, asPrefixContext: asPrefixContext, typePrinting: .functionStyle, hasName: true)
		case .functionSignatureSpecialization: printSpecializationPrefix(name, description: "function signature specialization")
		case .functionSignatureSpecializationParam: printFunctionSignatureSpecializationParam(name)
		case .functionSignatureSpecializationParamKind: printFunctionSignatureSpecializationParamKind(name)
		case .functionSignatureSpecializationParamPayload: target.write((try? parseMangledSwiftSymbol(name.text ?? "").description) ?? (name.text ?? ""))
		case .functionSignatureSpecializationReturn: printFunctionSignatureSpecializationParam(name)
		case .genericPartialSpecialization: printSpecializationPrefix(name, description: "generic partial specialization", paramPrefix: "Signature = ")
		case .genericPartialSpecializationNotReAbstracted: printSpecializationPrefix(name, description: "generic not re-abstracted partial specialization", paramPrefix: "Signature = ")
		case .genericProtocolWitnessTable: printFirstChild(name, prefix: "generic protocol witness table for ")
		case .genericProtocolWitnessTableInstantiationFunction: printFirstChild(name, prefix: "instantiation function for generic protocol witness table for ")
		case .genericSpecialization, .genericSpecializationInResilienceDomain: printSpecializationPrefix(name, description: "generic specialization")
		case .genericSpecializationNotReAbstracted: printSpecializationPrefix(name, description: "generic not re-abstracted specialization")
		case .genericSpecializationParam: printGenericSpecializationParam(name)
		case .genericSpecializationPrespecialized: printSpecializationPrefix(name, description: "generic pre-specialization")
		case .genericTypeMetadataPattern: printFirstChild(name, prefix: "generic type metadata pattern for ")
		case .genericTypeParamDecl: return printEntity(name, asPrefixContext: asPrefixContext, typePrinting: .noType, hasName: true)
		case .getter: return printAbstractStorage(name.children.first, asPrefixContext: asPrefixContext, extraName: "getter")
		case .global: printChildren(name)
		case .globalActorFunctionType: printGlobalActorFunctionType(name)
		case .globalGetter: return printAbstractStorage(name.children.first, asPrefixContext: asPrefixContext, extraName: "getter")
		case .globalVariableOnceDeclList: printGlobalVariableOnceDeclList(name)
		case .globalVariableOnceFunction, .globalVariableOnceToken: printGlobalVariableOnceFunction(name)
		case .hasSymbolQuery: target.write("#_hasSymbol query for ")
		case .identifier: target.write(name.text ?? "")
		case .implConvention: target.write(name.text ?? "")
		case .implCoroutineKind: printImplCoroutineKind(name)
		case .implDifferentiabilityKind: printImplDifferentiabilityKind(name)
		case .implErasedIsolation: target.write("@isolated(any)")
		case .implErrorResult: printChildren(name, prefix: "@error ", separator: " ")
		case .implParameter, .implResult: printImplParameter(name)
		case .implEscaping: target.write("@escaping")
		case .implFunctionAttribute: target.write(name.text ?? "")
		case .implFunctionConvention: printImplFunctionConvention(name)
		case .implFunctionConventionName: break
		case .implFunctionType: printImplFunctionType(name)
		case .implicitClosure: return printEntity(name, asPrefixContext: asPrefixContext, typePrinting: options.contains(.showFunctionArgumentTypes) ? .functionStyle : .noType, hasName: false, extraName: "implicit closure #", extraIndex: (name.children.at(1)?.index ?? 0) + 1)
		case .implInvocationSubstitutions: printImplInvocationSubstitutions(name)
		case .implParameterResultDifferentiability: printImplParameterName(name)
		case .implParameterSending: printImplParameterName(name)
		case .implPatternSubstitutions: printImplPatternSubstitutions(name)
		case .implSendingResult: target.write("sending")
		case .implYield: printChildren(name, prefix: "@yields ", separator: " ")
		case .index: target.write("\(name.index ?? 0)")
		case .indexSubset: printIndexSubset(name)
		case .infixOperator: target.write("\(name.text ?? "") infix")
		case .initAccessor: return printAbstractStorage(name.children.first, asPrefixContext: asPrefixContext, extraName: "init")
		case .initializer: return printEntity(name, asPrefixContext: asPrefixContext, typePrinting: .noType, hasName: false, extraName: "variable initialization expression")
		case .inlinedGenericFunction: printSpecializationPrefix(name, description: "inlined generic function")
		case .inOut: printFirstChild(name, prefix: "inout ")
		case .integer: target.write("\(name.index ?? 0)")
		case .isolated: printFirstChild(name, prefix: "isolated ")
		case .isolatedAnyFunctionType: target.write("@isolated(any) ")
		case .isolatedDeallocator: return printEntity(name, asPrefixContext: asPrefixContext, typePrinting: .noType, hasName: false, extraName: name.children.first?.kind == .class ? "__isolated_deallocating_deinit" : "deinit")
		case .isSerialized: target.write("serialized")
		case .iVarDestroyer: return printEntity(name, asPrefixContext: asPrefixContext, typePrinting: .noType, hasName: false, extraName: "__ivar_destroyer")
		case .iVarInitializer: return printEntity(name, asPrefixContext: asPrefixContext, typePrinting: .noType, hasName: false, extraName: "__ivar_initializer")
		case .keyPathEqualsThunkHelper, .keyPathHashThunkHelper: printKeyPathEqualityThunkHelper(name)
		case .keyPathGetterThunkHelper, .keyPathSetterThunkHelper: printKeyPathAccessorThunkHelper(name)
		case .labelList: break
		case .lazyProtocolWitnessTableAccessor: printLazyProtocolWitnesstableAccessor(name)
		case .lazyProtocolWitnessTableCacheVariable: printLazyProtocolWitnesstableCacheVariable(name)
		case .localDeclName: _ = printOptional(name.children.at(1), suffix: " #\((name.children.at(0)?.index ?? 0) + 1)")
		case .macro: return printEntity(name, asPrefixContext: asPrefixContext, typePrinting: name.children.count == 3 ? .withColon : .functionStyle, hasName: true)
		case .macroExpansionLoc: printMacroExpansionLoc(name)
		case .macroExpansionUniqueName: return printEntity(name, asPrefixContext: asPrefixContext, typePrinting: .noType, hasName: true, extraName: "unique name #", extraIndex: (name.children.at(2)?.index ?? 0) + 1)
		case .materializeForSet: return printAbstractStorage(name.children.first, asPrefixContext: asPrefixContext, extraName: "materializeForSet")
		case .memberAttachedMacroExpansion: return printMacro(name: name, asPrefixContext: asPrefixContext, label: "member")
		case .memberAttributeAttachedMacroExpansion: return printMacro(name: name, asPrefixContext: asPrefixContext, label: "memberAttribute")
		case .mergedFunction: target.write(!options.contains(.shortenThunk) ? "merged " : "")
		case .metaclass: printFirstChild(name, prefix: "metaclass for ")
		case .metadataInstantiationCache: printFirstChild(name, prefix: "metadata instantiation cache for ")
		case .metatype: printMetatype(name)
		case .metatypeRepresentation: target.write(name.text ?? "")
		case .methodDescriptor: printFirstChild(name, prefix: "method descriptor for ")
		case .methodLookupFunction: printFirstChild(name, prefix: "method lookup function for ")
		case .modify2Accessor: return printAbstractStorage(name.children.first, asPrefixContext: asPrefixContext, extraName: "modify2")
		case .modifyAccessor: return printAbstractStorage(name.children.first, asPrefixContext: asPrefixContext, extraName: "modify")
		case .module: printModule(name)
		case .moduleDescriptor: printFirstChild(name, prefix: "module descriptor ")
		case .nativeOwningAddressor: return printAbstractStorage(name.children.first, asPrefixContext: asPrefixContext, extraName: "nativeOwningAddressor")
		case .nativeOwningMutableAddressor: return printAbstractStorage(name.children.first, asPrefixContext: asPrefixContext, extraName: "nativeOwningMutableAddressor")
		case .nativePinningAddressor: return printAbstractStorage(name.children.first, asPrefixContext: asPrefixContext, extraName: "nativePinningAddressor")
		case .nativePinningMutableAddressor: return printAbstractStorage(name.children.first, asPrefixContext: asPrefixContext, extraName: "nativePinningMutableAddressor")
		case .negativeInteger: target.write("-\(name.index ?? 0)")
		case .noDerivative: printFirstChild(name, prefix: "@noDerivative ")
		case .nominalTypeDescriptor: printFirstChild(name, prefix: "nominal type descriptor for ")
		case .nominalTypeDescriptorRecord: printFirstChild(name, prefix: "nominal type descriptor runtime record for ")
		case .noncanonicalSpecializedGenericTypeMetadata: printFirstChild(name, prefix: "noncanonical specialized generic type metadata for ")
		case .noncanonicalSpecializedGenericTypeMetadataCache: printFirstChild(name, prefix: "cache variable for noncanonical specialized generic type metadata for ")
		case .nonObjCAttribute: target.write("@nonobjc ")
		case .nonUniqueExtendedExistentialTypeShapeSymbolicReference: target.writeHex(prefix: "non-unique existential shape symbolic reference 0x", name.index ?? 0)
		case .number: target.write("\(name.index ?? 0)")
		case .objCAsyncCompletionHandlerImpl, .predefinedObjCAsyncCompletionHandlerImpl: printObjCAsyncCompletionHandlerImpl(name)
		case .objCAttribute: target.write("@objc ")
		case .objCMetadataUpdateFunction: printFirstChild(name, prefix: "ObjC metadata update function for ")
		case .objCResilientClassStub: printFirstChild(name, prefix: "ObjC resilient class stub for ")
		case .objectiveCProtocolSymbolicReference: target.writeHex(prefix: "objective-c protocol symbolic reference 0x", name.index ?? 0)
		case .opaqueReturnType: target.write("some")
		case .opaqueReturnTypeIndex: break
		case .opaqueReturnTypeOf: printChildren(name, prefix: "<<opaque return type of ", suffix: ">>")
		case .opaqueReturnTypeParent: break
		case .opaqueType: printOpaqueType(name)
		case .opaqueTypeDescriptor: printFirstChild(name, prefix: "opaque type descriptor for ")
		case .opaqueTypeDescriptorAccessor: printFirstChild(name, prefix: "opaque type descriptor accessor for ")
		case .opaqueTypeDescriptorAccessorImpl: printFirstChild(name, prefix: "opaque type descriptor accessor impl for ")
		case .opaqueTypeDescriptorAccessorKey: printFirstChild(name, prefix: "opaque type descriptor accessor key for ")
		case .opaqueTypeDescriptorAccessorVar: printFirstChild(name, prefix: "opaque type descriptor accessor var for ")
		case .opaqueTypeDescriptorRecord: printFirstChild(name, prefix: "opaque type descriptor runtime record for ")
		case .opaqueTypeDescriptorSymbolicReference: target.writeHex(prefix: "opaque type symbolic reference 0x", name.index ?? 0)
		case .otherNominalType: return printEntity(name, asPrefixContext: asPrefixContext, typePrinting: .noType, hasName: true)
		case .outlinedAssignWithCopy, .outlinedAssignWithCopyNoValueWitness: printFirstChild(name, prefix: "outlined assign with copy of ")
		case .outlinedAssignWithTake, .outlinedAssignWithTakeNoValueWitness: printFirstChild(name, prefix: "outlined assign with take of ")
		case .outlinedBridgedMethod: target.write("outlined bridged method (\(name.text ?? "")) of ")
		case .outlinedConsume: printFirstChild(name, prefix: "outlined consume of ")
		case .outlinedCopy: printFirstChild(name, prefix: "outlined copy of ")
		case .outlinedDestroy, .outlinedDestroyNoValueWitness: printFirstChild(name, prefix: "outlined destroy of ")
		case .outlinedEnumGetTag: printFirstChild(name, prefix: "outlined enum get tag of ")
		case .outlinedEnumProjectDataForLoad: printFirstChild(name, prefix: "outlined enum project data for load of ")
		case .outlinedEnumTagStore: printFirstChild(name, prefix: "outlined enum tag store of ")
		case .outlinedInitializeWithCopy, .outlinedInitializeWithCopyNoValueWitness: printFirstChild(name, prefix: "outlined init with copy of ")
		case .outlinedInitializeWithTake: printFirstChild(name, prefix: "outlined init with take of ")
		case .outlinedReadOnlyObject: target.write("outlined read-only object #\(name.index ?? 0) of ")
		case .outlinedRelease: printFirstChild(name, prefix: "outlined release of ")
		case .outlinedRetain: printFirstChild(name, prefix: "outlined retain of ")
		case .outlinedVariable: target.write("outlined variable #\(name.index ?? 0) of ")
		case .owned: printFirstChild(name, prefix: "__owned ")
		case .owningAddressor: return printAbstractStorage(name.children.first, asPrefixContext: asPrefixContext, extraName: "owningAddressor")
		case .owningMutableAddressor: return printAbstractStorage(name.children.first, asPrefixContext: asPrefixContext, extraName: "owningMutableAddressor")
		case .pack: printChildren(name, prefix: "Pack{", suffix: "}", separator: ", ")
		case .packElement: printFirstChild(name, prefix: "/* level: \(name.children.at(1)?.index ?? 0) */ each ")
		case .packElementLevel: break
		case .packExpansion: printFirstChild(name, prefix: "repeat ")
		case .packProtocolConformance: printChildren(name, prefix: "pack protocol conformance ")
		case .partialApplyForwarder: printPartialApplyForwarder(name)
		case .partialApplyObjCForwarder: printPartialApplyObjCForwarder(name)
		case .peerAttachedMacroExpansion: return printMacro(name: name, asPrefixContext: asPrefixContext, label: "peer")
		case .postfixOperator: target.write("\(name.text ?? "") postfix")
		case .prefixOperator: target.write("\(name.text ?? "") prefix")
		case .privateDeclName: printPrivateDeclName(name)
		case .propertyDescriptor: printFirstChild(name, prefix: "property descriptor for ")
		case .propertyWrapperBackingInitializer: return printEntity(name, asPrefixContext: asPrefixContext, typePrinting: .noType, hasName: false, extraName: "property wrapper backing initializer")
		case .propertyWrapperInitFromProjectedValue: return printEntity(name, asPrefixContext: asPrefixContext, typePrinting: .noType, hasName: false, extraName: "property wrapper init from projected value")
		case .protocolConformance: printProtocolConformance(name)
		case .protocolConformanceDescriptor: printFirstChild(name, prefix: "protocol conformance descriptor for ")
		case .protocolConformanceDescriptorRecord: printFirstChild(name, prefix: "protocol conformance descriptor runtime record for ")
		case .protocolConformanceRefInOtherModule: printChildren(name, prefix: "protocol conformance ref (retroactive) ")
		case .protocolConformanceRefInProtocolModule: printChildren(name, prefix: "protocol conformance ref (protocol's module) ")
		case .protocolConformanceRefInTypeModule: printChildren(name, prefix: "protocol conformance ref (type's module) ")
		case .protocolDescriptor: printFirstChild(name, prefix: "protocol descriptor for ")
		case .protocolDescriptorRecord: printFirstChild(name, prefix: "protocol descriptor runtime record for ")
		case .protocolList: printProtocolList(name)
		case .protocolListWithAnyObject: printProtocolListWithAnyObject(name)
		case .protocolListWithClass: printProtocolListWithClass(name)
		case .protocolRequirementsBaseDescriptor: printFirstChild(name, prefix: "protocol requirements base descriptor for ")
		case .protocolSelfConformanceDescriptor: printFirstChild(name, prefix: "protocol self-conformance descriptor for ")
		case .protocolSelfConformanceWitness: printFirstChild(name, prefix: "protocol self-conformance witness for ")
		case .protocolSelfConformanceWitnessTable: printFirstChild(name, prefix: "protocol self-conformance witness table for ")
		case .protocolSymbolicReference: target.write("protocol symbolic reference \(String(format:"0x%X", name.index ?? 0))")
		case .protocolWitness: printProtocolWitness(name)
		case .protocolWitnessTable: printFirstChild(name, prefix: "protocol witness table for ")
		case .protocolWitnessTableAccessor: printFirstChild(name, prefix: "protocol witness table accessor for ")
		case .protocolWitnessTablePattern: printFirstChild(name, prefix: "protocol witness table pattern for ")
		case .reabstractionThunk, .reabstractionThunkHelper: printReabstractionThunk(name)
		case .reabstractionThunkHelperWithGlobalActor: printReabstracctionThunkHelperWithGlobalActor(name)
		case .reabstractionThunkHelperWithSelf: printReabstractionThunkHelperWithSelf(name)
		case .read2Accessor: return printAbstractStorage(name.children.first, asPrefixContext: asPrefixContext, extraName: "read2")
		case .readAccessor: return printAbstractStorage(name.children.first, asPrefixContext: asPrefixContext, extraName: "read")
		case .reflectionMetadataAssocTypeDescriptor: printFirstChild(name, prefix: "reflection metadata associated type descriptor ")
		case .reflectionMetadataBuiltinDescriptor: printFirstChild(name, prefix: "reflection metadata builtin descriptor ")
		case .reflectionMetadataFieldDescriptor: printFirstChild(name, prefix: "reflection metadata field descriptor ")
		case .reflectionMetadataSuperclassDescriptor: printFirstChild(name, prefix: "reflection metadata superclass descriptor ")
		case .relatedEntityDeclName: printFirstChild(name, prefix: "related decl '\(name.text ?? "")' for ")
		case .resilientProtocolWitnessTable: printFirstChild(name, prefix: "resilient protocol witness table for ")
		case .retroactiveConformance: printRetroactiveConformance(name)
		case .returnType: printReturnType(name)
		case .sending: printFirstChild(name, prefix: "sending ")
		case .sendingResultFunctionType: target.write("sending ")
		case .setter: return printAbstractStorage(name.children.first, asPrefixContext: asPrefixContext, extraName: "setter")
		case .shared: printFirstChild(name, prefix: "__shared ")
		case .silBoxImmutableField, .silBoxMutableField: printFirstChild(name, prefix: name.kind == .silBoxImmutableField ? "let " : "var ")
		case .silBoxLayout: printSequence(name.children, prefix: "{\(name.children.isEmpty ? "" : " ")", suffix: " }", separator: ", ")
		case .silBoxType: printFirstChild(name, prefix: "@box ")
		case .silBoxTypeWithLayout: printSilBoxTypeWithLayout(name)
		case .silPackDirect: printChildren(name, prefix: "@direct Pack{", suffix: "}", separator: ", ")
		case .silPackIndirect: printChildren(name, prefix: "@indirect Pack{", suffix: "}", separator: ", ")
		case .silThunkHopToMainActorIfNeeded: printFirstChild(name, prefix: "hop to main actor thunk of ")
		case .silThunkIdentity: printFirstChild(name, prefix: "identity thunk of ")
		case .specializationPassID: target.write("\(name.index ?? 0)")
		case .static: printFirstChild(name, prefix: "static ")
		case .subscript: return printEntity(name, asPrefixContext: asPrefixContext, typePrinting: .functionStyle, hasName: true, overwriteName: "subscript")
		case .suffix: printSuffix(name)
		case .sugaredArray: printFirstChild(name, prefix: "[", suffix: "]")
		case .sugaredDictionary: printSugaredDictionary(name)
		case .sugaredOptional: printSugaredOptional(name)
		case .sugaredParen: printFirstChild(name, prefix: "(", suffix: ")")
		case .symbolicExtendedExistentialType: printSymbolicExtendedExistentialType(name)
		case .throwsAnnotation: target.write(" throws")
		case .tuple: printChildren(name, prefix: "(", suffix: ")", separator: ", ")
		case .tupleElement: printTupleElement(name)
		case .tupleElementName: target.write("\(name.text ?? ""): ")
		case .type: printFirstChild(name)
		case .typedThrowsAnnotation: printTypeThrowsAnnotation(name)
		case .typeList: printChildren(name)
		case .typeMangling: printFirstChild(name)
		case .typeMetadata: printFirstChild(name, prefix: "type metadata for ")
		case .typeMetadataAccessFunction: printFirstChild(name, prefix: "type metadata accessor for ")
		case .typeMetadataCompletionFunction: printFirstChild(name, prefix: "type metadata completion function for ")
		case .typeMetadataDemanglingCache: printFirstChild(name, prefix: "demangling cache variable for type metadata for ")
		case .typeMetadataInstantiationCache: printFirstChild(name, prefix: "type metadata instantiation cache for ")
		case .typeMetadataInstantiationFunction: printFirstChild(name, prefix: "type metadata instantiation cache for ")
		case .typeMetadataLazyCache: printFirstChild(name, prefix: "lazy cache variable for type metadata for ")
		case .typeMetadataSingletonInitializationCache: printFirstChild(name, prefix: "type metadata singleton initialization cache for ")
		case .typeSymbolicReference: target.write("type symbolic reference \(String(format:"0x%X", name.index ?? 0))")
		case .uniquable: printFirstChild(name, prefix: "uniquable ")
		case .uniqueExtendedExistentialTypeShapeSymbolicReference: target.writeHex(prefix: "non-unique existential shape symbolic reference 0x", name.index ?? 0)
		case .unknownIndex: target.write("unknown index")
		case .unmanaged: printFirstChild(name, prefix: "unowned(unsafe) ")
		case .unowned: printFirstChild(name, prefix: "unowned ")
		case .unsafeAddressor: return printAbstractStorage(name.children.first, asPrefixContext: asPrefixContext, extraName: "unsafeAddressor")
		case .unsafeMutableAddressor: return printAbstractStorage(name.children.first, asPrefixContext: asPrefixContext, extraName: "unsafeMutableAddressor")
		case .valueWitness: printValueWitness(name)
		case .valueWitnessTable: printFirstChild(name, prefix: "value witness table for ")
		case .variable: return printEntity(name, asPrefixContext: asPrefixContext, typePrinting: .withColon, hasName: true)
		case .variadicMarker: target.write(" variadic-marker ")
		case .vTableAttribute: target.write("override ")
		case .vTableThunk: printVTableThunk(name)
		case .weak: printFirstChild(name, prefix: "weak ")
		case .willSet: return printAbstractStorage(name.children.first, asPrefixContext: asPrefixContext, extraName: "willset")
		}
		
		return nil
	}
	
	mutating func printAbstractStorage(_ name: SwiftSymbol?, asPrefixContext: Bool, extraName: String) -> SwiftSymbol? {
		guard let n = name else { return nil }
		switch n.kind {
		case .variable: return printEntity(n, asPrefixContext: asPrefixContext, typePrinting: .withColon, hasName: true, extraName: extraName)
		case .subscript: return printEntity(n, asPrefixContext: asPrefixContext, typePrinting: .withColon, hasName: false, extraName: extraName, extraIndex: nil, overwriteName: "subscript")
		default: return nil
		}
	}
	
	mutating func printEntityType(name: SwiftSymbol, type: SwiftSymbol, genericFunctionTypeList: SwiftSymbol?) {
		let labelList = name.children.first(where: { $0.kind == .labelList })
		if labelList != nil || genericFunctionTypeList != nil {
			if let gftl = genericFunctionTypeList {
				printChildren(gftl, prefix: "<", suffix: ">", separator: ", ")
			}
			var t = type
			if type.kind == .dependentGenericType {
				if genericFunctionTypeList == nil {
					_ = printOptional(type.children.first)
				}
				if let dt = type.children.at(1) {
					if dt.needSpaceBeforeType {
						target.write(" ")
					}
					if let first = dt.children.first {
						t = first
					}
				}
			}
			printFunctionType(labelList: labelList, t)
		} else {
			_ = printName(type)
		}
	}
	
	mutating func printEntity(_ name: SwiftSymbol, asPrefixContext: Bool, typePrinting: TypePrinting, hasName: Bool, extraName: String? = nil, extraIndex: UInt64? = nil, overwriteName: String? = nil) -> SwiftSymbol? {
		var genericFunctionTypeList: SwiftSymbol? = nil
		var name = name
		if name.kind == .boundGenericFunction, let first = name.children.at(0), let second = name.children.at(1) {
			name = first
			genericFunctionTypeList = second
		}
		
		let multiWordName = extraName?.contains(" ") == true || (hasName && name.children.at(1)?.kind == .localDeclName)
		if asPrefixContext && (typePrinting != .noType || multiWordName) {
			return name
		}
		
		guard let context = name.children.first else { return nil }
		var postfixContext: SwiftSymbol? = nil
		if shouldPrintContext(context) {
			if multiWordName {
				postfixContext = context
			} else {
				let currentPos = target.count
				postfixContext = printName(context, asPrefixContext: true)
				if target.count != currentPos {
					target.write(".")
				}
			}
		}
		
		var extraNameConsumed = extraName == nil
		if hasName || overwriteName != nil {
			if !extraNameConsumed && multiWordName {
				target.write(extraName ?? "")
				if let extraIndex {
					target.write("\(extraIndex)")
				}
				target.write(" of ")
				extraNameConsumed = true
			}
			let currentPos = target.count
			if let o = overwriteName {
				target.write(o)
			} else {
				if let one = name.children.at(1) {
					if one.kind != .privateDeclName {
						_ = printName(one)
					}
					if let pdn = name.children.first(where: { $0.kind == .privateDeclName }) {
						_ = printName(pdn)
					}
				}
			}
			if target.count != currentPos && !extraNameConsumed {
				target.write(".")
			}
		}
		if !extraNameConsumed {
			target.write(extraName ?? "")
			if let ei = extraIndex {
				target.write("\(ei)")
			}
		}
		if typePrinting != .noType {
			guard var type = name.children.first(where: { $0.kind == .type }) else { return nil }
			if type.kind != .type {
				guard let nextType = name.children.at(2) else { return nil }
				type = nextType
			}
			guard type.kind == .type, let firstChild = type.children.first else { return nil }
			type = firstChild
			var typePr = typePrinting
			if typePr == .functionStyle {
				var t = type
				while t.kind == .dependentGenericType, let next = t.children.at(1)?.children.at(0) {
					t = next
				}
				switch t.kind {
				case .functionType, .noEscapeFunctionType, .uncurriedFunctionType, .cFunctionPointer, .thinFunctionType: break
				default: typePr = .withColon
				}
			}
			if typePr == .withColon {
				if options.contains(.displayEntityTypes) {
					target.write(" : ")
					printEntityType(name: name, type: type, genericFunctionTypeList: genericFunctionTypeList)
				}
			} else {
				if multiWordName || type.needSpaceBeforeType {
					target.write(" ")
				}
				printEntityType(name: name, type: type, genericFunctionTypeList: genericFunctionTypeList)
			}
		}
		if !asPrefixContext, let pfc = postfixContext {
			switch name.kind {
			case .defaultArgumentInitializer, .initializer, .propertyWrapperBackingInitializer, .propertyWrapperInitFromProjectedValue:
				target.write(" of ")
			default:
				target.write(" in ")
			}
			_ = printName(pfc)
			return nil
		}
		return postfixContext
	}
	
	mutating func printSpecializationPrefix(_ name: SwiftSymbol, description: String, paramPrefix: String = "") {
		if !options.contains(.displayGenericSpecializations) {
			if !specializationPrefixPrinted {
				target.write("specialized ")
				specializationPrefixPrinted = true
			}
			return
		}
		target.write("\(description) <")
		var separator = ""
		var argNum = 0
		for c in name.children {
			switch c.kind {
			case .specializationPassID, .droppedArgument: break
			case .isSerialized:
				target.write(separator)
				separator = ", "
				_ = printName(c)
			default:
				if !c.children.isEmpty {
					target.write(separator)
					target.write(paramPrefix)
					separator = ", "
					switch c.kind {
					case .functionSignatureSpecializationParam:
						target.write("Arg[\(argNum)] = ")
						printFunctionSignatureSpecializationParam(c)
					case .functionSignatureSpecializationReturn:
						target.write("Return = ")
						printFunctionSignatureSpecializationParam(c)
					default:
						_ = printName(c)
					}
				}
				argNum += 1
			}
		}
		target.write("> of ")
	}
	
	mutating func printFunctionParameters(labelList: SwiftSymbol?, parameterType: SwiftSymbol, showTypes: Bool) {
		guard parameterType.kind == .argumentTuple else { return }
		guard let t = parameterType.children.first, t.kind == .type else { return }
		guard let parameters = t.children.first else { return }
		
		if parameters.kind != .tuple {
			if showTypes {
				target.write("(")
				_ = printName(parameters)
				target.write(")")
			} else {
				target.write("(_:)")
			}
			return
		}
		
		target.write("(")
		for tuple in parameters.children.enumerated() {
			if let label = labelList?.children.at(tuple.offset) {
				target.write("\(label.kind == .identifier ? (label.text ?? "") : "_"):")
				if showTypes {
					target.write(" ")
				}
			} else if !showTypes {
				if let label = tuple.element.children.first(where: { $0.kind == .tupleElementName }) {
					target.write("\(label.text ?? ""):")
				} else {
					target.write("_:")
				}
			}
			
			if showTypes {
				_ = printName(tuple.element)
				if tuple.offset != parameters.children.count - 1 {
					target.write(", ")
				}
			}
		}
		target.write(")")
	}
	
	mutating func printConventionWithMangledCType(_ name: SwiftSymbol, label: String) {
		target.write("@convention(\(label)")
		if let firstChild = name.children.first, firstChild.kind == .clangType {
			target.write(", mangledCType: \"")
			_ = printName(firstChild)
			target.write("\"")
		}
		target.write(") ")
	}
	
	mutating func printFunctionType(labelList: SwiftSymbol? = nil, _ name: SwiftSymbol) {
		switch name.kind {
		case .autoClosureType, .escapingAutoClosureType: target.write("@autoclosure ")
		case .thinFunctionType: target.write("@convention(thin) ")
		case .cFunctionPointer:
			printConventionWithMangledCType(name, label: "c")
		case .escapingObjCBlock:
			target.write("@escaping ")
			fallthrough
		case .objCBlock:
			printConventionWithMangledCType(name, label: "block")
		default: break
		}
		
		let argIndex = name.children.count - 2
		var startIndex = 0
		var isSendable = false
		var isAsync = false
		var hasSendingResult = false
		var diffKind = UnicodeScalar(0)
		if name.children.at(startIndex)?.kind == .clangType {
			startIndex += 1
		}
		if name.children.at(startIndex)?.kind == .sendingResultFunctionType {
			startIndex += 1
			hasSendingResult = true
		}
		if name.children.at(startIndex)?.kind == .isolatedAnyFunctionType {
			_ = printOptional(name.children.at(startIndex))
			startIndex += 1
		}
		if name.children.at(startIndex)?.kind == .globalActorFunctionType {
			_ = printOptional(name.children.at(startIndex))
			startIndex += 1
		}
		if name.children.at(startIndex)?.kind == .differentiableFunctionType {
			diffKind = UnicodeScalar(UInt8(name.children.at(startIndex)?.index ?? 0))
			startIndex += 1
		}
		var thrownErrorNode: SwiftSymbol?
		if name.children.at(startIndex)?.kind == .throwsAnnotation || name.children.at(startIndex)?.kind == .typedThrowsAnnotation  {
			thrownErrorNode = name.children.at(startIndex)
			startIndex += 1
		}
		if name.children.at(startIndex)?.kind == .concurrentFunctionType {
			startIndex += 1
			isSendable = true
		}
		if name.children.at(startIndex)?.kind == .asyncAnnotation {
			startIndex += 1
			isAsync = true
		}
		
		switch diffKind {
		case "f": target.write("@differentiable(_forward) ")
		case "r": target.write("@differentiable(reverse) ")
		case "l": target.write("@differentiable(_linear) ")
		case "d": target.write("@differentiable ")
		default: break
		}
		
		if isSendable {
			target.write("@Sendable ")
		}
		
		guard let parameterType = name.children.at(argIndex) else { return }
		printFunctionParameters(labelList: labelList, parameterType: parameterType, showTypes: options.contains(.showFunctionArgumentTypes))
		if !options.contains(.showFunctionArgumentTypes) {
			return
		}
		if isAsync {
			target.write(" async")
		}
		if let thrownErrorNode {
			_ = printName(thrownErrorNode)
		}
		target.write(" -> ")
		if hasSendingResult {
			target.write("sending ")
		}
		
		_ = printOptional(name.children.at(argIndex + 1))
	}
	
	mutating func printBoundGenericNoSugar(_ name: SwiftSymbol) {
		guard let typeList = name.children.at(1) else { return }
		printFirstChild(name)
		printChildren(typeList, prefix: "<", suffix: ">", separator: ", ")
	}
	
	func findSugar(_ name: SwiftSymbol) -> SugarType {
		guard let firstChild = name.children.at(0) else { return .none }
		if name.children.count == 1, firstChild.kind == .type { return findSugar(firstChild) }
		
		guard name.kind == .boundGenericEnum || name.kind == .boundGenericStructure else { return .none }
		guard let secondChild = name.children.at(1) else { return .none }
		guard name.children.count == 2 else { return .none }
		
		guard let unboundType = firstChild.children.first, unboundType.children.count > 1 else { return .none }
		let typeArgs = secondChild
		
		let c0 = unboundType.children.at(0)
		let c1 = unboundType.children.at(1)
		
		if name.kind == .boundGenericEnum {
			if c1?.isIdentifier(desired: "Optional") == true && typeArgs.children.count == 1 && c0?.isSwiftModule == true {
				return .optional
			}
			if c1?.isIdentifier(desired: "ImplicitlyUnwrappedOptional") == true && typeArgs.children.count == 1 && c0?.isSwiftModule == true {
				return .implicitlyUnwrappedOptional
			}
			return .none
		}
		if c1?.isIdentifier(desired: "Array") == true && typeArgs.children.count == 1 && c0?.isSwiftModule == true {
			return .array
		}
		if c1?.isIdentifier(desired: "Dictionary") == true && typeArgs.children.count == 2 && c0?.isSwiftModule == true {
			return .dictionary
		}
		return .none
	}
	
	mutating func printBoundGeneric(_ name: SwiftSymbol) {
		guard name.children.count >= 2 else { return }
		guard name.children.count == 2, options.contains(.synthesizeSugarOnTypes), name.kind != .boundGenericClass else {
			printBoundGenericNoSugar(name)
			return
		}
		
		if name.kind == .boundGenericProtocol {
			_ = printOptional(name.children.at(1))
			_ = printOptional(name.children.at(0), prefix: " as ")
			return
		}
		
		let sugarType = findSugar(name)
		switch sugarType {
		case .optional, .implicitlyUnwrappedOptional:
			if let type = name.children.at(1)?.children.at(0) {
				let needParens = !type.isSimpleType
				_ = printOptional(type, prefix: needParens ? "(" : "", suffix: needParens ? ")" : "")
				target.write(sugarType == .optional ? "?" : "!")
			}
		case .array, .dictionary:
			_ = printOptional(name.children.at(1)?.children.at(0), prefix: "[")
			if sugarType == .dictionary {
				_ = printOptional(name.children.at(1)?.children.at(1), prefix: " : ")
			}
			target.write("]")
		default: printBoundGenericNoSugar(name)
		}
	}
	
	mutating func printImplFunctionType(_ name: SwiftSymbol) {
		enum State: Int { case attrs, inputs, results }
		var curState: State = .attrs
		var patternSubs: SwiftSymbol?
		var invocationSubs: SwiftSymbol?
		var sendingResult: SwiftSymbol?
		let transitionTo = { (printer: inout SymbolPrinter, newState: State) -> Void in
			while curState != newState {
				switch curState {
				case .attrs:
					if let patternSubs {
						printer.printFirstChild(patternSubs, prefix: "@substituted ", suffix: " ")
					}
					printer.target.write("(")
				case .inputs:
					printer.target.write(") -> ")
					if let sendingResult {
						_ = printer.printName(sendingResult)
						printer.target.write(" ")
					}
					printer.target.write("(")
				case .results: break
				}
				guard let nextState = State(rawValue: curState.rawValue + 1) else { break }
				curState = nextState
			}
		}
		childLoop: for c in name.children {
			if c.kind == .implParameter {
				if curState == .inputs {
					target.write(", ")
				}
				transitionTo(&self, .inputs)
				_ = printName(c)
			} else if c.kind == .implResult || c.kind == .implYield || c.kind == .implErrorResult {
				if curState == .results {
					target.write(", ")
				}
				transitionTo(&self, .results)
				_ = printName(c)
			} else if c.kind == .implPatternSubstitutions {
				patternSubs = c
			} else if c.kind == .implInvocationSubstitutions {
				invocationSubs = c
			} else if c.kind == .implSendingResult {
				sendingResult = c
				
			} else {
				_ = printName(c)
				target.write(" ")
			}
		}
		transitionTo(&self, .results)
		target.write(")")
		if let patternSubs, let second = patternSubs.children.at(1) {
			printChildren(second, prefix: " for <", suffix: ">")
		}
		if let invocationSubs, let second = invocationSubs.children.at(0) {
			printChildren(second, prefix: " for <", suffix: ">")
		}
	}
	
	mutating func quotedString(_ value: String) {
		target.write("\"")
		for c in value.unicodeScalars {
			switch c {
			case "\\": target.write("\\\\")
			case "\t": target.write("\\t")
			case "\n": target.write("\\n")
			case "\r": target.write("\\r")
			case "\"": target.write("\\\"")
			case "\0": target.write("\\0")
			default:
				if c < UnicodeScalar(0x20) || c == UnicodeScalar(0x7f) {
					target.write("\\x")
					target.write(String(describing: ((c.value >> 4) > 9) ? UnicodeScalar(c.value + UnicodeScalar("A").value) : UnicodeScalar(c.value + UnicodeScalar("0").value)))
				} else {
					target.write(String(c))
				}
			}
		}
		target.write("\"")
	}
}

fileprivate extension TextOutputStream {
	mutating func write(conditional: Bool, _ value: String) {
		if conditional {
			write(value)
		}
	}
}

extension FunctionSigSpecializationParamKind {
	var description: String {
		switch self {
		case .boxToValue: return "Value Promoted from Box"
		case .boxToStack: return "Stack Promoted from Box"
		case .constantPropFunction: return "Constant Propagated Function"
		case .constantPropGlobal: return "Constant Propagated Global"
		case .constantPropInteger: return "Constant Propagated Integer"
		case .constantPropFloat: return "Constant Propagated Float"
		case .constantPropKeyPath: return "Constant Propagated KeyPath"
		case .constantPropString: return "Constant Propagated String"
		case .closureProp: return "Closure Propagated"
		case .existentialToGeneric: return "Existential To Protocol Constrained Generic"
		case .dead: return "Dead"
		case .inOutToOut: return "InOut Converted to Out"
		case .ownedToGuaranteed: return "Owned To Guaranteed"
		case .guaranteedToOwned: return "Guaranteed To Owned"
		case .sroa: return "Exploded"
		}
	}
}

// MARK: ScalarScanner.swift

/// A type for representing the different possible failure conditions when using ScalarScanner
public enum SwiftSymbolParseError: Error {
	/// Attempted to convert the buffer to UnicodeScalars but the buffer contained invalid data
	case utf8ParseError
	
	case punycodeParseError
	
	/// The scalar at the specified index doesn't match the expected grammar
	case unexpected(at: Int)
	
	/// Expected `wanted` at offset `at`
	case matchFailed(wanted: String, at: Int)
	
	/// Expected numerals at offset `at`
	case expectedInt(at: Int)
	
	/// Attempted to read `count` scalars from position `at` but hit the end of the sequence
	case endedPrematurely(count: Int, at: Int)
	
	/// Unable to find search patter `wanted` at or after `after` in the sequence
	case searchFailed(wanted: String, after: Int)
	
	case integerOverflow(at: Int)
	
	case unimplementedFeature
}

/// NOTE: This extension is fileprivate to avoid clashing with CwlUtils (from which it is taken). If you want to use these functions outside this file, consider including CwlUtils.
private extension UnicodeScalar {
	/// Tests if the scalar is within a range
	func isInRange(_ range: ClosedRange<UnicodeScalar>) -> Bool {
		return range.contains(self)
	}
	
	/// Tests if the scalar is a plain ASCII digit
	var isDigit: Bool {
		return ("0"..."9").contains(self)
	}
	
	/// Tests if the scalar is a plain ASCII English alphabet lowercase letter
	var isLower: Bool {
		return ("a"..."z").contains(self)
	}
	
	/// Tests if the scalar is a plain ASCII English alphabet uppercase letter
	var isUpper: Bool {
		return ("A"..."Z").contains(self)
	}
	
	/// Tests if the scalar is a plain ASCII English alphabet letter
	var isLetter: Bool {
		return isLower || isUpper
	}
}

/// NOTE: This struct is fileprivate to avoid clashing with CwlUtils (from which it is taken). If you want to use this struct outside this file, consider including CwlUtils.
///
/// A structure for traversing a `String.UnicodeScalarView`.
///
/// **UNICODE WARNING**: this struct ignores all Unicode combining rules and parses each scalar individually. The rules for parsing must allow combined characters to be parsed separately or better yet, forbid combining characters at critical parse locations. If your data structure does not include these types of rule then you should be iterating over the `Character` elements in a `String` rather than using this struct.
fileprivate struct ScalarScanner<C: Collection> where C.Iterator.Element == UnicodeScalar {
	/// The underlying storage
	let scalars: C
	
	/// Current scanning index
	var index: C.Index
	
	/// Number of scalars consumed up to `index` (since String.UnicodeScalarView.Index is not a RandomAccessIndex, this makes determining the position *much* easier)
	var consumed: Int
	
	/// Construct from a String.UnicodeScalarView and a context value
	init(scalars: C) {
		self.scalars = scalars
		self.index = self.scalars.startIndex
		self.consumed = 0
	}
	
	/// Sets the index back to the beginning and clears the consumed count
	mutating func reset() {
		index = scalars.startIndex
		consumed = 0
	}
	
	/// Throw if the scalars at the current `index` don't match the scalars in `value`. Advance the `index` to the end of the match.
	/// WARNING: `string` is used purely for its `unicodeScalars` property and matching is purely based on direct scalar comparison (no decomposition or normalization is performed).
	mutating func match(string: String) throws {
		let (newIndex, newConsumed) = try string.unicodeScalars.reduce((index: index, count: 0)) { (tuple: (index: C.Index, count: Int), scalar: UnicodeScalar) in
			if tuple.index == self.scalars.endIndex || scalar != self.scalars[tuple.index] {
				throw SwiftSymbolParseError.matchFailed(wanted: string, at: consumed)
			}
			return (index: self.scalars.index(after: tuple.index), count: tuple.count + 1)
		}
		index = newIndex
		consumed += newConsumed
	}
	
	/// Throw if the scalars at the current `index` don't match the scalars in `value`. Advance the `index` to the end of the match.
	mutating func match(scalar: UnicodeScalar) throws {
		if index == scalars.endIndex || scalars[index] != scalar {
			throw SwiftSymbolParseError.matchFailed(wanted: String(scalar), at: consumed)
		}
		index = self.scalars.index(after: index)
		consumed += 1
	}
	
	/// Throw if the scalars at the current `index` don't match the scalars in `value`. Advance the `index` to the end of the match.
	mutating func match(where test: @escaping (UnicodeScalar) -> Bool) throws {
		if index == scalars.endIndex || !test(scalars[index]) {
			throw SwiftSymbolParseError.matchFailed(wanted: "(match test function to succeed)", at: consumed)
		}
		index = self.scalars.index(after: index)
		consumed += 1
	}
	
	/// Throw if the scalars at the current `index` don't match the scalars in `value`. Advance the `index` to the end of the match.
	mutating func read(where test: @escaping (UnicodeScalar) -> Bool) throws -> UnicodeScalar {
		if index == scalars.endIndex || !test(scalars[index]) {
			throw SwiftSymbolParseError.matchFailed(wanted: "(read test function to succeed)", at: consumed)
		}
		let s = scalars[index]
		index = self.scalars.index(after: index)
		consumed += 1
		return s
	}
	
	/// Consume scalars from the contained collection, up to but not including the first instance of `scalar` found. `index` is advanced to immediately before `scalar`. Returns all scalars consumed prior to `scalar` as a `String`. Throws if `scalar` is never found.
	mutating func readUntil(scalar: UnicodeScalar) throws -> String {
		var i = index
		let previousConsumed = consumed
		try skipUntil(scalar: scalar)
		
		var result = ""
		result.reserveCapacity(consumed - previousConsumed)
		while i != index {
			result.unicodeScalars.append(scalars[i])
			i = scalars.index(after: i)
		}
		
		return result
	}
	
	/// Consume scalars from the contained collection, up to but not including the first instance of `string` found. `index` is advanced to immediately before `string`. Returns all scalars consumed prior to `string` as a `String`. Throws if `string` is never found.
	/// WARNING: `string` is used purely for its `unicodeScalars` property and matching is purely based on direct scalar comparison (no decomposition or normalization is performed).
	mutating func readUntil(string: String) throws -> String {
		var i = index
		let previousConsumed = consumed
		try skipUntil(string: string)
		
		var result = ""
		result.reserveCapacity(consumed - previousConsumed)
		while i != index {
			result.unicodeScalars.append(scalars[i])
			i = scalars.index(after: i)
		}
		
		return result
	}
	
	/// Consume scalars from the contained collection, up to but not including the first instance of any character in `set` found. `index` is advanced to immediately before `string`. Returns all scalars consumed prior to `string` as a `String`. Throws if no matching characters are ever found.
	mutating func readUntil(set inSet: Set<UnicodeScalar>) throws -> String {
		var i = index
		let previousConsumed = consumed
		try skipUntil(set: inSet)
		
		var result = ""
		result.reserveCapacity(consumed - previousConsumed)
		while i != index {
			result.unicodeScalars.append(scalars[i])
			i = scalars.index(after: i)
		}
		
		return result
	}
	
	/// Peeks at the scalar at the current `index`, testing it with function `f`. If `f` returns `true`, the scalar is appended to a `String` and the `index` increased. The `String` is returned at the end.
	mutating func readWhile(true test: (UnicodeScalar) -> Bool) -> String {
		var string = ""
		while index != scalars.endIndex {
			if !test(scalars[index]) {
				break
			}
			string.unicodeScalars.append(scalars[index])
			index = self.scalars.index(after: index)
			consumed += 1
		}
		return string
	}
	
	/// Repeatedly peeks at the scalar at the current `index`, testing it with function `f`. If `f` returns `true`, the `index` increased. If `false`, the function returns.
	mutating func skipWhile(true test: (UnicodeScalar) -> Bool) {
		while index != scalars.endIndex {
			if !test(scalars[index]) {
				return
			}
			index = self.scalars.index(after: index)
			consumed += 1
		}
	}
	
	/// Consume scalars from the contained collection, up to but not including the first instance of `scalar` found. `index` is advanced to immediately before `scalar`. Throws if `scalar` is never found.
	mutating func skipUntil(scalar: UnicodeScalar) throws {
		var i = index
		var c = 0
		while i != scalars.endIndex && scalars[i] != scalar {
			i = self.scalars.index(after: i)
			c += 1
		}
		if i == scalars.endIndex {
			throw SwiftSymbolParseError.searchFailed(wanted: String(scalar), after: consumed)
		}
		index = i
		consumed += c
	}
	
	/// Consume scalars from the contained collection, up to but not including the first instance of any scalar from `set` is found. `index` is advanced to immediately before `scalar`. Throws if `scalar` is never found.
	mutating func skipUntil(set inSet: Set<UnicodeScalar>) throws {
		var i = index
		var c = 0
		while i != scalars.endIndex && !inSet.contains(scalars[i]) {
			i = self.scalars.index(after: i)
			c += 1
		}
		if i == scalars.endIndex {
			throw SwiftSymbolParseError.searchFailed(wanted: "One of: \(inSet.sorted())", after: consumed)
		}
		index = i
		consumed += c
	}
	
	/// Consume scalars from the contained collection, up to but not including the first instance of `string` found. `index` is advanced to immediately before `string`. Throws if `string` is never found.
	/// WARNING: `string` is used purely for its `unicodeScalars` property and matching is purely based on direct scalar comparison (no decomposition or normalization is performed).
	mutating func skipUntil(string: String) throws {
		let match = string.unicodeScalars
		guard let first = match.first else { return }
		if match.count == 1 {
			return try skipUntil(scalar: first)
		}
		var i = index
		var j = index
		var c = 0
		var d = 0
		let remainder = match[match.index(after: match.startIndex)..<match.endIndex]
		outerLoop: repeat {
			while scalars[i] != first {
				if i == scalars.endIndex {
					throw SwiftSymbolParseError.searchFailed(wanted: String(match), after: consumed)
				}
				i = self.scalars.index(after: i)
				c += 1
				
				// Track the last index and consume count before hitting the match
				j = i
				d = c
			}
			i = self.scalars.index(after: i)
			c += 1
			for s in remainder {
				if i == self.scalars.endIndex {
					throw SwiftSymbolParseError.searchFailed(wanted: String(match), after: consumed)
				}
				if scalars[i] != s {
					continue outerLoop
				}
				i = self.scalars.index(after: i)
				c += 1
			}
			break
		} while true
		index = j
		consumed += d
	}
	
	/// Attempt to advance the `index` by count, returning `false` and `index` unchanged if `index` would advance past the end, otherwise returns `true` and `index` is advanced.
	mutating func skip(count: Int = 1) throws {
		if count == 1 && index != scalars.endIndex {
			index = scalars.index(after: index)
			consumed += 1
		} else {
			var i = index
			var c = count
			while c > 0 {
				if i == scalars.endIndex {
					throw SwiftSymbolParseError.endedPrematurely(count: count, at: consumed)
				}
				i = self.scalars.index(after: i)
				c -= 1
			}
			index = i
			consumed += count
		}
	}
	
	/// Attempt to advance the `index` by count, returning `false` and `index` unchanged if `index` would advance past the end, otherwise returns `true` and `index` is advanced.
	mutating func backtrack(count: Int = 1) throws {
		if count <= consumed {
			if count == 1 {
				index = scalars.index(index, offsetBy: -1)
				consumed -= 1
			} else {
				let limit = consumed - count
				while consumed != limit {
					index = scalars.index(index, offsetBy: -1)
					consumed -= 1
				}
			}
		} else {
			throw SwiftSymbolParseError.endedPrematurely(count: -count, at: consumed)
		}
	}
	
	/// Returns all content after the current `index`. `index` is advanced to the end.
	mutating func remainder() -> String {
		var string: String = ""
		while index != scalars.endIndex {
			string.unicodeScalars.append(scalars[index])
			index = scalars.index(after: index)
			consumed += 1
		}
		return string
	}
	
	/// If the next scalars after the current `index` match `value`, advance over them and return `true`, otherwise, leave `index` unchanged and return `false`.
	/// WARNING: `string` is used purely for its `unicodeScalars` property and matching is purely based on direct scalar comparison (no decomposition or normalization is performed).
	mutating func conditional(string: String) -> Bool {
		var i = index
		var c = 0
		for s in string.unicodeScalars {
			if i == scalars.endIndex || s != scalars[i] {
				return false
			}
			i = self.scalars.index(after: i)
			c += 1
		}
		index = i
		consumed += c
		return true
	}
	
	/// If the next scalar after the current `index` match `value`, advance over it and return `true`, otherwise, leave `index` unchanged and return `false`.
	mutating func conditional(scalar: UnicodeScalar) -> Bool {
		if index == scalars.endIndex || scalar != scalars[index] {
			return false
		}
		index = self.scalars.index(after: index)
		consumed += 1
		return true
	}
	
	/// If the next scalar after the current `index` match `value`, advance over it and return `true`, otherwise, leave `index` unchanged and return `false`.
	mutating func conditional(where test: (UnicodeScalar) -> Bool) -> UnicodeScalar? {
		if index == scalars.endIndex || !test(scalars[index]) {
			return nil
		}
		let s = scalars[index]
		index = self.scalars.index(after: index)
		consumed += 1
		return s
	}
	
	/// If the `index` is at the end, throw, otherwise, return the next scalar at the current `index` without advancing `index`.
	func requirePeek() throws -> UnicodeScalar {
		if index == scalars.endIndex {
			throw SwiftSymbolParseError.endedPrematurely(count: 1, at: consumed)
		}
		return scalars[index]
	}
	
	/// If `index` + `ahead` is within bounds, return the scalar at that location, otherwise return `nil`. The `index` will not be changed in any case.
	func peek(skipCount: Int = 0) -> UnicodeScalar? {
		var i = index
		var c = skipCount
		while c > 0 && i != scalars.endIndex {
			i = self.scalars.index(after: i)
			c -= 1
		}
		if i == scalars.endIndex {
			return nil
		}
		return scalars[i]
	}
	
	/// If the `index` is at the end, throw, otherwise, return the next scalar at the current `index`, advancing `index` by one.
	mutating func readScalar() throws -> UnicodeScalar {
		if index == scalars.endIndex {
			throw SwiftSymbolParseError.endedPrematurely(count: 1, at: consumed)
		}
		let result = scalars[index]
		index = self.scalars.index(after: index)
		consumed += 1
		return result
	}
	
	/// Throws if scalar at the current `index` is not in the range `"0"` to `"9"`. Consume scalars `"0"` to `"9"` until a scalar outside that range is encountered. Return the integer representation of the value scanned, interpreted as a base 10 integer. `index` is advanced to the end of the number.
	mutating func readInt() throws -> UInt64 {
		let result = try conditionalInt()
		guard let r = result else {
			throw SwiftSymbolParseError.expectedInt(at: consumed)
		}
		return r
	}
	
	/// Throws if scalar at the current `index` is not in the range `"0"` to `"9"`. Consume scalars `"0"` to `"9"` until a scalar outside that range is encountered. Return the integer representation of the value scanned, interpreted as a base 10 integer. `index` is advanced to the end of the number.
	mutating func conditionalInt() throws -> UInt64? {
		var result: UInt64 = 0
		var i = index
		var c = 0
		while i != scalars.endIndex && scalars[i].isDigit {
			let digit = UInt64(scalars[i].value - UnicodeScalar("0").value)
			
			// The Swift compiler allows overflow here for malformed inputs, so we're obliged to do the same
			result = result &* 10 &+ digit
			
			i = self.scalars.index(after: i)
			c += 1
		}
		if i == index {
			return nil
		}
		index = i
		consumed += c
		return result
	}
	
	/// Consume and return `count` scalars. `index` will be advanced by count. Throws if end of `scalars` occurs before consuming `count` scalars.
	mutating func readScalars(count: Int) throws -> String {
		var result = String()
		result.reserveCapacity(count)
		var i = index
		for _ in 0..<count {
			if i == scalars.endIndex {
				throw SwiftSymbolParseError.endedPrematurely(count: count, at: consumed)
			}
			result.unicodeScalars.append(scalars[i])
			i = self.scalars.index(after: i)
		}
		index = i
		consumed += count
		return result
	}
	
	/// Returns a throwable error capturing the current scanner progress point.
	func unexpectedError() -> SwiftSymbolParseError {
		return SwiftSymbolParseError.unexpected(at: consumed)
	}
	
	var isAtEnd: Bool {
		return index == scalars.endIndex
	}
}

fileprivate extension String {
	mutating func writeHex(prefix: String? = nil, _ value: UInt64) {
		if let prefix = prefix {
			write(prefix)
		}
		write(String(format: "%llX", value))
	}
}

fileprivate extension Array {
	func at(_ index: Int) -> Element? {
		return self.indices.contains(index) ? self[index] : nil
	}
	func slice(_ from: Int, _ to: Int) -> ArraySlice<Element> {
		if from > to || from > self.endIndex || to < self.startIndex {
			return ArraySlice()
		} else {
			return self[(from > self.startIndex ? from : self.startIndex)..<(to < self.endIndex ? to : self.endIndex)]
		}
	}
}
