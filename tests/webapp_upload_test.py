import csv
import os
import unittest
from io import BytesIO
from unittest.mock import patch

from flask import session
from mock import AsyncMock

from app.brivo_errors import BrivoError
from app.processing import EXPECTED_CSV_HEADERS
from tests.fixtures import CREATE_CSV_CORRECT
from tests.webapp_base import WebAppTestBase, get_flash


class WebAppUploadTestCase(WebAppTestBase):

    def test_upload_bad_file(self):
        with self.app.test_request_context("/"), self.app.test_client() as c:
            with c.session_transaction() as sess:
                self._login(sess)
            data = {
                "upload_type": "create",
                "file": (BytesIO(b"header1,header2\nvalue1,value2"), "test.csv"),
            }

            response = c.post(
                "/upload",
                data=data,
                content_type="multipart/form-data",
                follow_redirects=True,
            )
            self.assertIn("Invalid file format.", get_flash(response)[0])
            self.assertEqual(response.status_code, 200)

    def test_upload_non_csv_file(self):
        with self.app.test_request_context("/"), self.app.test_client() as c:
            with c.session_transaction() as sess:
                self._login(sess)
            data = {"upload_type": "create", "file": (BytesIO(b"1,2\n3,4"), "test.xls")}

            response = c.post(
                "/upload",
                data=data,
                content_type="multipart/form-data",
                follow_redirects=True,
            )
            self.assertEqual(response.status_code, 200)

            self.assertIn("Only CSV files are accepted", get_flash(response)[0])

    @patch("app.processing.remove_old_processed_files")
    @patch("app.processing.BrivoApiContext")
    def test_upload_correct_file_with_unhandled_exception(
        self, mock_get_brivo, mock_remove_old_processed_files
    ):
        mock_get_brivo.return_value.__aenter__.return_value = AsyncMock()
        mock_get_brivo.return_value.__aenter__.return_value.create_user = AsyncMock()
        # raise exception
        mock_get_brivo.return_value.__aenter__.return_value.create_user.side_effect = (
            Exception("Mocked exception")
        )
        with self.app.test_request_context("/"), self.app.test_client() as c:
            with c.session_transaction() as sess:
                sess["username"] = "test"
                sess["password"] = "testpass"
                self._login(sess)

            data = {
                "upload_type": "create",
                "file": (BytesIO(CREATE_CSV_CORRECT), "test.csv"),
            }
            response = c.post(
                "/upload",
                data=data,
                content_type="multipart/form-data",
                follow_redirects=True,
            )
            self.assertEqual(response.status_code, 200)
            self.assertIn(
                "Error during processing: Mocked exception", get_flash(response)[0]
            )
            mock_remove_old_processed_files.assert_called_once()

    @patch("app.processing.BrivoApiContext")
    def test_upload_correct_file(self, mock_get_brivo):
        mock_get_brivo.return_value.__aenter__.return_value = AsyncMock()
        mock_get_brivo.return_value.__aenter__.return_value.create_user = AsyncMock()
        with self.app.test_request_context("/"), self.app.test_client() as c:
            with c.session_transaction() as sess:
                sess["username"] = "test"
                sess["password"] = "testpass"
                self._login(sess)
            data = {
                "upload_type": "create",
                "file": (BytesIO(CREATE_CSV_CORRECT), "test.csv"),
            }
            response = c.post(
                "/upload",
                data=data,
                content_type="multipart/form-data",
                follow_redirects=True,
            )
            self.assertEqual(response.status_code, 200)
            self.assertIn("Total records: 2.", response.text)
            self.assertIn("Failed records: 0.", response.text)
            self.assertTrue(os.path.isfile(session["_last_csv_results_file"]))
            # for some reason, the file is not being closed in testing

            response.close()
            response = c.get("/download_result")
            self.assertEqual(response.status_code, 200)
            self.assertIn(
                "First,Last,Member ID,Group,Card Number,Facility Code,Error",
                response.text,
            )
            # for some reason, the file is not being closed in testing
            response.close()

    @patch("app.processing.BrivoApiContext")
    def test_upload_correct_file_with_failing_user(self, mock_get_brivo):

        def create_user_mock(*args, **kwargs):
            # emulate fail on second user
            if kwargs["first_name"] == "First2":
                raise BrivoError("Mocked BrivoApiError")
            else:
                return AsyncMock()

        mock_get_brivo.return_value.__aenter__.return_value = AsyncMock()
        mock_get_brivo.return_value.__aenter__.return_value.create_user.side_effect = (
            create_user_mock
        )

        with self.app.test_request_context("/"), self.app.test_client() as c:
            with c.session_transaction() as sess:
                self._login(sess)
                sess["username"] = "test"
                sess["password"] = "testpass"

            data = {
                "upload_type": "create",
                "file": (BytesIO(CREATE_CSV_CORRECT), "test.csv"),
            }
            response = c.post(
                "/upload",
                data=data,
                content_type="multipart/form-data",
                follow_redirects=True,
            )
            self.assertEqual(response.status_code, 200)
            self.assertIn("Total records: 2.", response.text)
            self.assertIn("Failed records: 1.", response.text)

            self.assertTrue(os.path.isfile(session["_last_csv_results_file"]))
            rows = []
            with open(session["_last_csv_results_file"], "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    rows.append(row)
                self.assertEqual(EXPECTED_CSV_HEADERS["create"].union(["Error"]), set(reader.fieldnames))  # type: ignore
            self.assertEqual(2, len(rows))
            self.assertEqual("Success", rows[1]["Error"])
            self.assertEqual("Mocked BrivoApiError", rows[0]["Error"])

        self.assertEqual(
            2,
            mock_get_brivo.return_value.__aenter__.return_value.create_user.call_count,
        )
        args, kwargs = (
            mock_get_brivo.return_value.__aenter__.return_value.create_user.call_args
        )
        self.assertEqual(["AS members", "Members"], kwargs["group_names"])


if __name__ == "__main__":
    unittest.main()
