import Foundation
import PDFKit
import Vision
import CoreGraphics

// All PDF bytes, rendered pixels, and recognized text remain in this process's memory.
func run() throws {
    let data = FileHandle.standardInput.readDataToEndOfFile()
    guard data.count <= 10485760, let doc = PDFDocument(data: data), !doc.isEncrypted, doc.pageCount <= 40 else { throw NSError(domain:"input", code:1) }
    var output: [[String: Any]] = []
    for index in 0..<doc.pageCount {
        try autoreleasepool {
            guard let page = doc.page(at:index) else { throw NSError(domain:"page", code:1) }
            let bounds = page.bounds(for: .mediaBox)
            let scale: CGFloat = 2.0
            let width = Int(ceil(bounds.width * scale)), height = Int(ceil(bounds.height * scale))
            guard width > 0, height > 0, width <= 6000, height <= 6000, width * height <= 12000000,
                  let ctx = CGContext(data:nil,width:width,height:height,bitsPerComponent:8,bytesPerRow:0,space:CGColorSpaceCreateDeviceRGB(),bitmapInfo:CGImageAlphaInfo.premultipliedLast.rawValue) else { throw NSError(domain:"size",code:1) }
            ctx.setFillColor(CGColor(red:1,green:1,blue:1,alpha:1)); ctx.fill(CGRect(x:0,y:0,width:width,height:height))
            ctx.scaleBy(x:scale,y:scale); ctx.translateBy(x:-bounds.minX,y:-bounds.minY); page.draw(with:.mediaBox,to:ctx)
            guard let image = ctx.makeImage() else { throw NSError(domain:"image",code:1) }
            let request = VNRecognizeTextRequest()
            request.recognitionLevel = .accurate; request.usesLanguageCorrection = false
            request.recognitionLanguages = ["zh-Hans", "en-US"]
            try VNImageRequestHandler(cgImage:image,options:[:]).perform([request])
            let lines = (request.results ?? []).compactMap { $0.topCandidates(1).first?.string }
            output.append(["page":index+1,"text":lines.joined(separator:"\n")])
        }
    }
    let encoded = try JSONSerialization.data(withJSONObject:output)
    FileHandle.standardOutput.write(encoded)
}
do { try run() } catch { exit(2) }
