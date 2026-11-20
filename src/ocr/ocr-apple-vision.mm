/*
obs-ytsucks - PII redaction filter for OBS Studio
Copyright (C) 2026 obs-ytsucks contributors

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program. If not, see <https://www.gnu.org/licenses/>
*/

// Apple Vision backend (macOS 10.15+, no extra dependencies).

#include "ocr-engine.hpp"

#import <CoreGraphics/CoreGraphics.h>
#import <Foundation/Foundation.h>
#import <Vision/Vision.h>

#include <cmath>

namespace pii {

    namespace {

        class AppleVisionEngine : public OcrEngine
        {
              public:
            bool init(const OcrConfig &config, std::string &)
            {
                language_ = config.language;
                fast_ = config.fast_mode;
                return true;
            }

            const char *name() const override
            {
                return "Apple Vision";
            }

            std::vector<OcrLine> recognize(const Image &img) override
            {
                std::vector<OcrLine> lines;
                if (img.empty() || img.channels != 4)
                    return lines;

                @autoreleasepool {
                    CFDataRef data =
                        CFDataCreate(kCFAllocatorDefault, img.pixels.data(), static_cast<CFIndex>(img.pixels.size()));
                    CGDataProviderRef provider = CGDataProviderCreateWithCFData(data);
                    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
                    CGImageRef cgimg = CGImageCreate(img.width, img.height, 8, 32, img.stride(), cs,
                                                     kCGBitmapByteOrder32Little | kCGImageAlphaNoneSkipFirst, provider,
                                                     nullptr, false, kCGRenderingIntentDefault);
                    CGColorSpaceRelease(cs);
                    CGDataProviderRelease(provider);
                    CFRelease(data);
                    if (!cgimg)
                        return lines;

                    VNRecognizeTextRequest *request = [[VNRecognizeTextRequest alloc] init];
                    request.recognitionLevel = fast_ ? VNRequestTextRecognitionLevelFast
                                                     : VNRequestTextRecognitionLevelAccurate;
                    // Language correction "fixes" phone numbers and e-mail addresses.
                    request.usesLanguageCorrection = NO;
                    if (!language_.empty())
                        request.recognitionLanguages = @[[NSString stringWithUTF8String:language_.c_str()]];

                    VNImageRequestHandler *handler = [[VNImageRequestHandler alloc] initWithCGImage:cgimg options:@ {}];
                    NSError *error = nil;
                    const BOOL ok = [handler performRequests:@[request] error:&error];
                    CGImageRelease(cgimg);
                    if (!ok)
                        return lines;

                    const double W = img.width;
                    const double H = img.height;
                    NSCharacterSet *ws = [NSCharacterSet whitespaceAndNewlineCharacterSet];

                    for (VNRecognizedTextObservation *obs in request.results) {
                        VNRecognizedText *best = [[obs topCandidates:1] firstObject];
                        if (!best)
                            continue;
                        NSString *s = best.string;
                        const NSUInteger len = s.length;
                        OcrLine line;

                        NSUInteger i = 0;
                        while (i < len) {
                            while (i < len && [ws characterIsMember:[s characterAtIndex:i]])
                                i++;
                            const NSUInteger start = i;
                            while (i < len && ![ws characterIsMember:[s characterAtIndex:i]])
                                i++;
                            if (i == start)
                                break;
                            const NSRange range = NSMakeRange(start, i - start);
                            NSError *boxErr = nil;
                            VNRectangleObservation *box = [best boundingBoxForRange:range error:&boxErr];
                            if (!box)
                                continue;
                            // Vision: normalised, origin bottom-left.
                            const CGRect bb = box.boundingBox;
                            const int x0 = static_cast<int>(std::floor(bb.origin.x * W));
                            const int x1 = static_cast<int>(std::ceil((bb.origin.x + bb.size.width) * W));
                            const int y0 = static_cast<int>(std::floor((1.0 - bb.origin.y - bb.size.height) * H));
                            const int y1 = static_cast<int>(std::ceil((1.0 - bb.origin.y) * H));

                            OcrWord w;
                            w.text = [[s substringWithRange:range] UTF8String] ?: "";
                            w.box = {x0, y0, x1 - x0, y1 - y0};
                            w.confidence = best.confidence * 100.0f;
                            line.words.push_back(std::move(w));
                        }
                        if (!line.words.empty())
                            lines.push_back(std::move(line));
                    }
                }
                return lines;
            }

              private:
            std::string language_;
            bool fast_ = false;
        };

    }  // namespace

    std::unique_ptr<OcrEngine> create_apple_vision_engine(const OcrConfig &config, std::string &error)
    {
        auto engine = std::make_unique<AppleVisionEngine>();
        if (!engine->init(config, error))
            return nullptr;
        return engine;
    }

}  // namespace pii
