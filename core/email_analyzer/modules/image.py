import pymupdf
import email
import zipfile
import io
import zxingcpp
from PIL import Image

#   https://www.kaggle.com/datasets/beatoa/spamassassin-public-corpus/data
def analyze_pdf():
    with open('./core/data/email-test/qr.eml', 'rb') as email_file:
        email_message = email.message_from_binary_file(email_file)
    for part in email_message.walk():
        if part.get_content_disposition() == 'attachment' or part.get_content_disposition() == 'inline':
            file_content = part.get_payload(decode=True)
            if part.get_filename() != None and part.get_content_type() == 'application/zip':
                with zipfile.ZipFile(file=io.BytesIO(file_content)) as z:
                    for name in z.namelist():
                        print(name)
                        if name.endswith('.pdf'):
                            pdf_bytes = z.read(name)
                            doc = pymupdf.open(stream=pdf_bytes, filetype='pdf')
                            for i, page in enumerate(doc):
                                pix = page.get_pixmap(dpi=200)
                                pix.save('.//core//outputs//'+f"page_from_zip-{i+1}.png")
                                print(page.get_text())
            if part.get_filename() != None and part.get_content_type() == 'application/pdf':
                doc = pymupdf.open(stream=file_content, filetype='pdf')
                for i, page in enumerate(doc):
                    pix = page.get_pixmap(dpi=200)
                    pix.save(f"page_direct-{i+1}.png")
                    print(page.get_text())
            if part.get_filename() != None and '.png' in part.get_filename():

                
                image = Image.open(io.BytesIO(file_content))

                
                results = zxingcpp.read_barcodes(image)

                
                return [result.text for result in results]

def analyze_qr():
    pass


if __name__ == '__main__':
    analyze_pdf()
